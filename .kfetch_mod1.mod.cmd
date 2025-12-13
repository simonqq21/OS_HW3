savedcmd_kfetch_mod1.mod := printf '%s\n'   kfetch_mod1.o | awk '!x[$$0]++ { print("./"$$0) }' > kfetch_mod1.mod
