"""Fixed trusted entry into the owning user/mount namespace; never authority."""

ENTER_VIEW = '''import os,sys
view,mount,user=map(int,sys.argv[1:4])
os.setns(user,0)
os.setns(mount,0)
root=os.open('..',os.O_RDONLY|os.O_DIRECTORY,dir_fd=view)
expected=os.fstat(view);actual=os.stat('view',dir_fd=root)
assert (expected.st_dev,expected.st_ino)==(actual.st_dev,actual.st_ino)
os.fchdir(root);os.chroot('.');os.chdir('/')
for descriptor in (view,mount,user,root):os.close(descriptor)
os.execv(sys.argv[4],sys.argv[4:])
'''
