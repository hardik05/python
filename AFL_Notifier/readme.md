AFL Notifier

this script will monitor afl crashes and hangs folders and send a direct message on specified twitter account as soon as it finds them. this is very useful when you dont want to repeatativly check the fuzzer vm or system.
this also has option to send ping pong message so that you know that fuzzing vm or machine is atleast up.

how to use?
1.you will need to get few api keys from twitter and enter in the "generate_config.py"
2. then run python generate_config.py, it will generate "settings.json" file
3. then run python afl_twitter_notify.py, thats it.

you will needs json lib and python-twitter for this script to work.

comments or suggestions?
feel free to mail me at hardik05 _AT(_ gmail.)_com

