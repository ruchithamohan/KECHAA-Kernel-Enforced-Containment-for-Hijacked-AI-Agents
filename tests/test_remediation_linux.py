"""Linux-only follow-up; explicit skips are not enforcement evidence."""
import errno
import json
import os
import platform
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from kechaa.common import KechaaError
from kechaa.policy import narrow_project_paths
from tests.support import Fixture


@unittest.skipUnless(platform.system() == 'Linux', 'requires Linux; macOS diagnostic tests cannot verify kernel controls')
class LinuxBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_mount_admission_with_synthetic_mountinfo(self):
        # Real descriptor/stat, synthetic mountinfo. This is a unit test, not a
        # bind-mount or mount-namespace enforcement experiment.
        from kechaa.backends.linux import workspace_filesystems
        st = self.f.a.stat()
        device = f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}'
        def entry(number, path, root='/', dev=device, kind='tmpfs'):
            return f'{number} 1 {dev} {root} {path} rw - {kind} tmpfs rw\n'
        valid = entry(10, self.f.a)
        with patch('kechaa.backends.linux.read_bounded', return_value=valid.encode()):
            self.assertEqual(workspace_filesystems([str(self.f.a)])[0]['path'], str(self.f.a))
            with self.assertRaises(KechaaError):
                workspace_filesystems([str(self.f.a.parent)])
        invalid = [entry(10, self.f.a, root='/subdir'),
                   valid + entry(11, self.f.b),
                   valid + entry(12, self.f.a / 'nested', dev='255:255'),
                   entry(10, self.f.a, kind='overlay')]
        for content in invalid:
            with patch('kechaa.backends.linux.read_bounded', return_value=content.encode()):
                with self.assertRaises(KechaaError):
                    workspace_filesystems([str(self.f.a)])

    def test_actual_landlock_reads_after_contract_intersection(self):
        from kechaa.backends.linux import landlock_abi, restrict_files
        try:
            abi = landlock_abi()
        except KechaaError as exc:
            self.skipTest('Landlock unavailable: ' + exc.code)
        if abi < 6:
            self.skipTest('Landlock ABI >= 6 required')
        child = self.f.a / 'child'
        child.mkdir()
        targets = [self.f.a / 'exact', child / 'inside', self.f.b / 'outside', self.f.runtime / 'dependency']
        for target in targets:
            target.write_text('fixture')
        alias = self.f.a / 'alias'
        alias.symlink_to(targets[2])
        reads = narrow_project_paths([str(self.f.a.parent), str(self.f.runtime)], [str(self.f.a.parent)], [str(self.f.a)])
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            result = {}
            try:
                with ExitStack() as stack:
                    restrict_files({'read': reads, 'write': [], 'execute': []}, stack)
                    for target in [*targets, alias, self.f.a.parent, self.f.a, child]:
                        try:
                            fd = os.open(target, os.O_RDONLY)
                            os.close(fd)
                            result[str(target)] = 0
                        except OSError as exc:
                            result[str(target)] = exc.errno
                os.write(write_fd, json.dumps(result).encode())
                os._exit(0)
            except BaseException:
                os._exit(2)
        os.close(write_fd)
        with os.fdopen(read_fd, 'rb') as stream:
            payload = stream.read()
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, 'Landlock child failed to install controls')
        result = json.loads(payload)
        for target in (targets[0], targets[1], targets[3], self.f.a, child):
            self.assertEqual(result[str(target)], 0)
        for target in (targets[2], alias, self.f.a.parent):
            self.assertEqual(result[str(target)], errno.EACCES)
