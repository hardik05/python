import json

# Enter your twitter keys/secrets as strings in the following fields
credentials = {}
credentials['CONSUMER_KEY'] = "ENTER YOUR TWITTER CONSUMER KEY HERE"
credentials['CONSUMER_SECRET'] = "ENTER CONSUMER SECRATE HERE"
credentials['ACCESS_TOKEN'] = "ENTER ACCESS TOKEN HERE"
credentials['ACCESS_SECRET'] = "ENTER ACCESS SECRET HERE"
#afl specific settings
credentials['CRASH_PATH'] = "ENTER AFL CRASHES FOLDER FULL PATH"
credentials['HANG_PATH'] = "ENTER AFL HANGS FOLDER FULL PATH"
#script settings
credentials['MONITOR_TIME'] = "10" #how often script should check for new crashes or hangs, in seconds
credentials['PING_TIME'] = "3600" #how often script should send pingpong DMs to twitter account?
#twitter handle you want to receive DMs.
credentials['TWITTER_HANDLE'] = "ENTER TWITTER ACCOUNT HERE" #twitter account where you want to receive DMs
credentials['PROJECT_NAME'] = "ENTER PROJECT NAME/MACHINE NAME HERE" #Enter project name or machine name which should be used to notify
                                                           #you on twitter like gdifuzz or gdivm ,Helpful if you are fuzzing
                                                           #multuple things and not sure which project/vm you are getting crashes.

# Save the credentials object to file
with open("settings.json", "w") as file:
    json.dump(credentials, file)
