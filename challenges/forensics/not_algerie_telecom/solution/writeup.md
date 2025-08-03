
Now as a forensic analyst, one of the most important things we would like to know from a system during analysis would be:

* Active processes
* Commands executed in the shell/terminal/Command prompt
* Hidden processes (if any) or Exited processes
* Browser History (This is very much subjective to the scenario involved)

And many more...

Now, to list the active or running processes, we use the help of the plugin  **pslist** .

Executing this command gives us a list of processes which were running when the memory dump was taken. The output of the command gives a fully formatted view which includes the name, PID, PPID, Threads, Handles, start time etc..

Observing closely, we notice some processes which require some attention.

* cmd.exe
* DumpIt.exe
* explorer.exe
* cmd.exe

  * This is the process responsible for the command prompt. Extracting the content from this process might give us the details as to what commands were executed in the system
* DumpIt.exe

  * This process was used by me to acquire the memory dump of the system.
* Explorer.exe

  * This process is the one which handles the File Explorer.

Now since we have seen that **cmd.exe** was running, let us try to see if there were any commands executed in the shell/terminal.

For this, we use the **cmdscan** plugin.

we notice a python file was executed. The executed command was `C:\Python27\python.exe C:\Users\hello\Desktop\demon.py.txt`

So our next step would be check if this python script sent any output to  **stdout** . For this, we use the **consoles** plugin.

We see that a certain string `335d366f5d6031767631707f` has been written out to  **stdout** . Now as one might observe, this is a **hex-encoded** string. Once we try to revert out the hex encoding, we get a gibberish text.

we will try to deduce some clues from the challenge description. The first one is the challenge name "env". Now there are certain system determined variables called **Environment variables**

To view the environment variables in a system, use the **envars** plugin. Going down the output, we see a strange variable by the name **Thanos** (Ah! so maybe that's why it was provided in the description.), the value of the variable is `xor and password`.

```
python3 vol.py -f Challenge.raw windows.envars.Envars
```

Now, we have 3 things in total:

* The gibberish text resulted from reverting the hex-encoded string
* Xor
* Password

Thinking for a while, makes us realise why the clue `xor` was provided. Let us try to attempt xor decoding on the gibberish text.

```
 python3 -c "a = bytes. fromhex('335d366f5d6031767631707f'); [print(''.join(chr(j ^ i) for j in a)) for i in range(255)]"
```

There are only 255 possibilities and if you see, the 3rd output is a suspicious text  **1_4m_b3tt3r}** . That looks like part of the flag.
