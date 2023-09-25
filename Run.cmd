sc create NullPfn type=kernel binPath="E:\Repositories\NullPfn\x64\Release\NullPfn.sys"

sc start NullPfn
pause
sc stop NullPfn
sc delete NullPfn