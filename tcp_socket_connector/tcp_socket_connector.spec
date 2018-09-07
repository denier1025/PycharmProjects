# -*- mode: python -*-

block_cipher = None


a = Analysis(['tcp_socket_connector.py'],
             pathex=['c:\\Documents\\GithubClones\\PycharmProjects\\tcp_socket_connector'],
             binaries=[],
             datas=[('c:\\Documents\\GithubClones\\PycharmProjects\\tcp_socket_connector\\tcp_ip_intro.pdf', '.'), ('c:\\Documents\\GithubClones\\PycharmProjects\\tcp_socket_connector\\dist\\WinRunUpdate.exe', '.')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='tcp_socket_connector',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=False )
