import  os
if __name__ == '__main__':
    from PyInstaller.__main__ import run
    opts=['main.py', '--hidden-import=queue', '-F', '--version-file', 'file_version.txt']
    run(opts)