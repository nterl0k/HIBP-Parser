# HIBP Parser
PowerShell based parser for HaveIBeenPwned.com JSON reports. 

![HIBPParser](https://github.com/nterl0k/HIBP-Parser/blob/master/Images/pwnedlogo.png)

Feed it a JSON Domain Report from "Have I Been Pwned", pretty simple. This requires signing up for domain monitoring through Have I Been Pwned. This can be done at the following link.

https://haveibeenpwned.com/DomainSearch



The following variables in the script should be tailored to the environment to ensure that the email function works correctly:

- $EmailT = "securityteam@company.org"  
- $EmailF = "Security Team<security@company.org>"  
- $EmailSub = "Security Action: Breach Reporting"   
- $EmailSvr = "smtp.company.org"   
- $SecurityTeamName = "Security Team"	
- $CompanyName = "My Company"

### Download JSON report
Use the following command to start the process.

New-HaveIBeenPwndParse.ps1 -JSONURL "link here"

![HIBPParser2](https://github.com/nterl0k/HIBP-Parser/blob/master/Images/Image002.png)

### Main Menu
Main menu has 3 basic options.
- Serach for a specific breach data.
- Search for specific paste data.
- Search for one or more uaers in the breach/paste data.

All options will check AD if the user is a valid account based on email to AD filtering. It will then check the breach data date to see if the AD account may be in danger of password guessing.


![HIBPParser3](https://github.com/nterl0k/HIBP-Parser/blob/master/images/image003.png)

### Report Output
Each report option will allow for multiple output formats:
- Display on screen (shown below).
- Export a CSV to desktop
- Email report. Includes minor verbiage and CSV attached
    - Also includes the default distro in the script config but will allow for other targets as well.

![HIBPParser1](https://github.com/nterl0k/HIBP-Parser/blob/master/images/image001.png)
