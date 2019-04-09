<#
.SYNOPSIS
    Script to making pulling/parsing valid user accounts from a HIBP domain notice.

.DESCRIPTION
    A script that will download the JOSN URL from a HIBP subscription, then parse
    the contents of the download into some usable meterics as well as allow for seraching
    of the data for specific breach info and user account validity. Requires AD module for 
    powershell to function.

.PARAMETER JSONURL
    Input the JSON URL download link here.

.EXAMPLE
    C:\PS>./New-HaveIBeenPwndParse.ps1 
            This runs the command in default mode, will propt for JSON URL 

.NOTES
    Author: Nterl0k
    Date:   March 30, 2019    
#>

Param(
    
    [Parameter(HelpMessage="Please enter the JSON report URL.",Mandatory=$True)]    
    [ValidateNotNullOrEmpty()]
    [string]$JSONURL
    
)

#Set some helper variables.
$Tab = [char]9

#Set up SSL tolerance
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12';
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols ;

#Define user-agent to prevent script blocking
$Agent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36" ;

#Global Arrays because i'm too lazy to cast/return variables for these.
$Global:UserArray = @() 
$Global:UserArrayValid = @()

#Setup Default Email Reporting values (for email sending)
$EmailT = "securityteam@company.org"                                            	#CHANGEME - Should be a default recipients address.
$EmailF = "Security Team<security@company.org>"           				#CHANGEME - Should be a valid from address.
$EmailSub = "Security Action: Breach Reporting"                         		#CHANGEME - Email subject.
$EmailSvr = "smtp.company.org"                                                   	#CHANGEME - Your smtp server address.

#General HTML/Report Formatting (for email reports)
$SecurityTeamName = "Security Team"				                      	#CHANGEME - Your security team name.
$CompanyName = "My Company"                                                           	#CHANGEME - Your company name.
$FontType = "calibri"                                                                 	#CHANGEME - The font/style used for emiling.
[int]$FontSize = "11"                                                                 	#CHANGEME - The font/style used for emiling.
$FormatStart = "<span style=`'font-family:$($FontType);font-size:$($FontSize)pt;`'>"  	#CHANGEME - The font/style used for emiling.
$FormatEnd = "</span>"                                                                	#CHANGEME - The font/style used for emiling.
$TableHeader = @"                                                                     
<style>
TABLE {
border-width: 1px;
border-style: solid;
border-color: black;
border-collapse: collapse;
font-size: $($FontSize)pt;
font-family: $($FontType);
}

TH {
border-width: 1px;
padding: 3px;
border-style: solid;
border-color: black;
background-color: #CDCDCD;
font-size: $($FontSize)pt;
font-family: $($FontType);
font-weight: bold;
color: #000000;
}

TD {
border-width: 1px;
padding: 3px;
border-style: solid;
border-color: black;
font-size: $($FontSize)pt;
font-family: $($FontType);
color: #000000;
}
</style>
"@  

#Collect JSON formatted dump and convert to object
Try{
    $pwndjson = Invoke-WebRequest -Uri $JSONURL -UserAgent $Agent;
    $Pwnd = $pwndjson | ConvertFrom-Json
    If($Pwnd.BreachSearchResults -eq $null -and $Pwnd.PasteSearchResults -eq $null){
    Throw
    }
    Else{
            #Breach Stats  
            Write-Host "Please wait while some information is parsed about current breaches..." -ForegroundColor Yellow
            $BreachStats = "" | Select 'Breached Accounts','Unique Breaches','Latest Breach','Most Frequent Breach','Least Frequent Breach','-','Pasted Accounts','Unique Pastes','Latest Paste','Most Frequent Paste','Least Frequent Paste'
            $Domains = $pwnd.BreachSearchResults.DomainName | Sort-Object -Unique -Property DomainName 
            $Titles  = $Pwnd.BreachSearchResults.Breaches | Select Title, Domain, BreachDate, Description, AddedDate | Sort-Object -Unique -Descending -Property AddedDate
            $BreachCounts = $Pwnd.BreachSearchResults.Breaches.Title | Group-Object | Sort-Object -Descending -Property Count

            $PasteTitles = $Pwnd.PasteSearchResults.Pastes | Select Source, Id, Title, Date | Sort-Object -Unique -Descending -Property Date
            $PasteCounts = $Pwnd.PasteSearchResults.Pastes.ID  | Group-Object | Sort-Object -Descending -Property Count
                
            $BreachStats.'Breached Accounts' =  $Pwnd.BreachSearchResults.Count
            $BreachStats.'Unique Breaches' = $Titles.Count
            $BreachStats.'Latest Breach' = $Titles[0].Title
            $BreachStats.'Most Frequent Breach' = $BreachCounts[0].Name
            $BreachStats.'Least Frequent Breach' = $BreachCounts[-1].Name

            $BreachStats.'Pasted Accounts' =  $Pwnd.PasteSearchResults.Count
            $BreachStats.'Unique Pastes' =  $PasteTitles.Count
            $BreachStats.'Latest Paste' =  "$($PasteTitles[0].Source) - $($PasteTitles[0].ID)"
            $BreachStats.'Most Frequent Paste' = $PasteCounts[0].Name
            $BreachStats.'Least Frequent Paste' = $PasteCounts[-1].Name
                      
    }
}
Catch{
    #Quit function is report set is empty or cannot be reached.
    Write-Host "Could not retreive data from $JSONURL, please check the link and try again." -ForegroundColor Red
    Pause
    Exit
}

#Test for Ad Module instal.
Try{
    Get-ADuser $env:USERNAME | Out-Null
    }
Catch{
    Write-Host "AD Module for PowerShell must be installed for this script to function" -ForegroundColor Red
    Pause
    Exit
    }


Function StartMenu{
Clear-Host
Write-host "Welcome to the HaveIBeenPwned Parser script. - Nterl0k 2019

Current Data:
$Tab Report Target: " -ForegroundColor Green -NoNewline
Write-host "$JSONURL" -ForegroundColor Yellow
Write-host "$Tab Included Domains: " -ForegroundColor Green -NoNewline
Write-host "$Domains" -ForegroundColor Yellow
Write-host "
Current Data Stats:"  -ForegroundColor Green -NoNewline
$BreachStats | Out-host 

Write-host "What would you like to do?
"  -ForegroundColor Green

Write-Host "1) Report on a specific breach(es)" -ForegroundColor Magenta -NoNewline 
Write-Host "$Tab- Inspect specific breach(es) for users + AD stats."
Write-Host "2) Report on a specific paste dump(s)" -ForegroundColor Magenta -NoNewline 
Write-Host "$Tab- Inspect specific paste dump(s) for users + AD stats."
Write-Host "3) Report on a specific user account(s)" -ForegroundColor Magenta -NoNewline 
Write-Host "$Tab- Inspect a specific user for breach data + AD stats."
Write-Host "4) Quit" -ForegroundColor Magenta -NoNewline 
Write-Host "$Tab$Tab$Tab$Tab$Tab- Quit this application.
"
 
    $GetIn = Read-Host "Choose An Option"
    Clear-Host
    Switch ($GetIn){
    1 {
            #Breach information
            $Global:UserArray = @()
            $Global:UserArrayValid = @()
            BreachReport
            Output
            pause
            StartMenu
        }   
    2 {
            #Paste Section Here
            $Global:UserArray = @()
            $Global:UserArrayValid = @()
            PasteReport
            Output
            pause
            StartMenu
        }

    3 {
            #User Section Here
            $Global:UserArray = @()
            $Global:UserArrayValid = @()
            UserReport
            Output
            pause
            StartMenu
        }   
    4 {
            #Exit Function
            Exit
        }
    Default{
    StartMenu
        }
    }
}

Function BreachReport{
            $BreachArray = $Titles
            
            Write-Host "Latest breach reported: " -ForegroundColor Magenta -NoNewline
            Write-Host "$($Titles[0].Title)" -ForegroundColor Red -NoNewline
            Write-Host " on " -NoNewline
            Write-Host "$($Titles[0].AddedDate)
            " -ForegroundColor Red
            Write-Host "1) Select new breach." -ForegroundColor Yellow 
            Write-Host "2) Return
            " -ForegroundColor Yellow            
            $GetIn = Read-Host "Select Option: (Press enter to use $($Titles[0].Title))"
            Switch ($GetIn){
                    1{
                    Write-Host "Current Breach Data will be displayed." -foreground Yellow
                    pause
                    $BreachArray | Select Title,Domain,BreachDate,AddedDate | FT -AutoSize -Wrap

                    $BreachReportTemp = Read-Host "Enter a breach name (Use `"All`" for all breaches)"
                    If ($BreachArray.Title -eq $BreachReportTemp){
                        Write-Host "Found $BreachReportTemp, setting as new target" -ForegroundColor Green
                        $BreachReport = $BreachReportTemp
                        
                        }
                    ElseIf($BreachReportTemp -eq "All"){
                        Write-Host "Checking all users may take a while, are you sure? (Default No)" -ForegroundColor Yellow
                        $confirm = Read-Host "(Y/N)"
                        Switch ($confirm){
                            Y {
                                $BreachReport = $BreachReportTemp
                                
                            }
                            N {
                                StartMenu
                            }
                            Default{
                                StartMenu
                            }
                        }
                    }
                    Else{
                        Write-Host "Couldn't find $BreachReportTemp." -ForegroundColor Red
                        pause
                        }
                    }
                    2{
                        StartMenu
                    }
                    Default{
                        $BreachReport = $Titles[0].Title
                    }                       
                }

            If ($BreachReport -ne ""){
                Write-Host "Collecting valid user account stats from: " -NoNewline
                Write-Host "$BreachReport
                " -Foreground Red -NoNewline

                Foreach($Account in $pwnd.BreachSearchResults){
                    Write-Progress -Activity "Checking Account Stats" -Status "User: $($Account.Alias)@$($Account.DomainName)" -PercentComplete (($pwnd.BreachSearchResults.indexof($Account)/$pwnd.BreachSearchResults.Count)*100)

                    If(($Account.Breaches.Title -eq $BreachReport) -or ($BreachReport -eq "All")){
                    $UserAccount = "$($Account.Alias)@$($Account.DomainName)"
                    $ADUserInfo = Get-aduser -Filter {mail -like $UserAccount} -Properties *                   
                    sleep -Milliseconds 50            
                    
                    Foreach($Breach in $Account.Breaches){
                        If(($Breach.Title -eq $BreachReport) -or ($BreachReport -eq "All")){
                            $UserArrayO = "" | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Department,AD_Office,AD_Company,AD_Enabled,AD_LastPssRst;
                            $UserArrayO.Account = $UserAccount
                            $UserArrayO.BreachName = $Breach.Title
                            $UserArrayO.BreachType = "Breach"
                            $UserArrayO.BreachDate = if($Breach.BreachDate){[DateTime]$Breach.BreachDate}

                            If($ADUserInfo.SAMAccountName -ne $null){
                                $UserArrayO.AD_UserID = $ADUserInfo.SAMAccountName
                                $UserArrayO.AD_Department = $ADUserInfo.department
                                $UserArrayO.AD_Office = $ADUserInfo.office
                                $UserArrayO.AD_Company = $ADUserInfo.company
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.AD_LastPssRst = $ADUserInfo.PasswordLastSet
                             }
                            Else {
                                $UserArrayO.AD_UserID = "AD Account not found"
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.Account_At_Risk = $False
                                $UserArrayO.Account_Valid = $False
                                }


                    
                            If($ADUserInfo.SAMAccountName -ne $null -and $ADUserInfo.enabled -eq $True){
                                $UserArrayO.Account_Valid = $True                        
                                If($ADUserInfo.PasswordLastSet -lt $Breach.BreachDate){
                                    $UserArrayO.Account_At_Risk = $True
                                }
                                Else{
                                    $UserArrayO.Account_At_Risk = $false
                                }
                                }
                            Else{
                                $UserArrayO.Account_Valid = $False
                                }
                                     
                          $Global:UserArray += $UserArrayO
                          }
                      }
                  }
                }
                Write-Progress -Activity "Checking Account Stats" -Completed
            }
            Write-Host ""
            Write-Host "Breach reporting complete." -ForegroundColor Green 
            Write-Host "Stripping invalid accounts." -ForegroundColor yellow
            $Global:UserArrayValid = $Global:UserArray | Where-Object {$_.Account_Valid -ne $false}          

}

Function PasteReport{
            $BreachArray= $PasteTitles
            
            Write-Host "Latest paste dump reported: " -ForegroundColor Magenta -NoNewline
            Write-Host "$($PasteTitles[0].Source) - $($PasteTitles[0].Id)" -ForegroundColor Red -NoNewline
            Write-Host " on " -NoNewline
            Write-Host "$($PasteTitles[0].Date)
            " -ForegroundColor Red
            Write-Host "1) Select new paste dump." -ForegroundColor Yellow 
            Write-Host "2) Return
            " -ForegroundColor Yellow            
            $GetIn = Read-Host "Select Option: (Press enter to use $($PasteTitles[0].Source) - $($PasteTitles[0].Id))"
            Switch ($GetIn){
                    1{
                    Write-Host "Current Paste Dumps will be displayed." -foreground Yellow
                    pause
                    $BreachArray | Select ID,Source,Title,Date | FT -AutoSize -Wrap

                    $BreachReportTemp = Read-Host "Enter a paste dump *ID* (Use `"All`" for all paste dumps)"
                    If ($BreachArray.ID -eq $BreachReportTemp){
                        Write-Host "Found $BreachReportTemp, setting as new target" -ForegroundColor Green
                        $BreachReport = $BreachReportTemp
                        
                        }
                    ElseIf($BreachReportTemp -eq "All"){
                        Write-Host "Checking all users may take a while, are you sure? (Default No)" -ForegroundColor Yellow
                        $confirm = Read-Host "(Y/N)"
                        Switch ($confirm){
                            Y {
                                $BreachReport = $BreachReportTemp
                                
                            }
                            N {
                                StartMenu
                            }
                            Default{
                                StartMenu
                            }
                        }
                    }
                    Else{
                        Write-Host "Couldn't find $BreachReportTemp." -ForegroundColor Red
                        pause
                        }
                    }
                    2{
                        StartMenu
                    }
                    Default{
                        $BreachReport = $PasteTitles[0].ID
                    }                       
                }

            If ($BreachReport -ne ""){
                Write-Host "Collecting valid user account stats from: " -NoNewline
                Write-Host "$BreachReport
                " -Foreground Red -NoNewline

                Foreach($Account in $pwnd.PasteSearchResults){
                    Write-Progress -Activity "Checking Account Stats" -Status "User: $($Account.Alias)@$($Account.DomainName)" -PercentComplete (($pwnd.PasteSearchResults.indexof($Account)/$pwnd.PasteSearchResults.Count)*100)

                    If(($Account.Pastes.Id -eq $BreachReport) -or ($BreachReport -eq "All")){
                    $UserAccount = "$($Account.Alias)@$($Account.DomainName)"
                    $ADUserInfo = Get-aduser -Filter {mail -like $UserAccount} -Properties *
                    sleep -Milliseconds 50
                                
                    Foreach($Breach in $Account.Pastes){
                        IF(($Account.Pastes.Id -eq $BreachReport) -or ($BreachReport -eq "All")){
                            $UserArrayO = "" | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Department,AD_Office,AD_Company,AD_Enabled,AD_LastPssRst;
                            $UserArrayO.Account = $UserAccount
                            $UserArrayO.BreachName = $Breach.Id
                            $UserArrayO.BreachType = "Paste"
                            $UserArrayO.BreachDate = If($Breach.Date){[DateTime]$Breach.Date}

                            If($ADUserInfo.SAMAccountName -ne $null){
                                $UserArrayO.AD_UserID = $ADUserInfo.SAMAccountName
                                $UserArrayO.AD_Department = $ADUserInfo.department
                                $UserArrayO.AD_Office = $ADUserInfo.office
                                $UserArrayO.AD_Company = $ADUserInfo.company
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.AD_LastPssRst = $ADUserInfo.PasswordLastSet
                             }
                            Else {
                                $UserArrayO.AD_UserID = "AD Account not found"
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.Account_At_Risk = $False
                                $UserArrayO.Account_Valid = $False
                                }


                    
                            If($ADUserInfo.SAMAccountName -ne $null -and $ADUserInfo.enabled -eq $True){
                                $UserArrayO.Account_Valid = $True                  
                                If($ADUserInfo.PasswordLastSet -lt $Breach.Date){
                                    $UserArrayO.Account_At_Risk = $True
                                }
                                Else{
                                    $UserArrayO.Account_At_Risk = $false
                                }
                                }
                            Else{
                                $UserArrayO.Account_Valid = $False
                                }
                                     
                          $Global:UserArray += $UserArrayO
                          }
                      }
                  }
                }
                Write-Progress -Activity "Checking Account Stats" -Completed
            }

            Write-Host ""
            Write-Host "Breach Reporting Complete." -ForegroundColor Green 
            Write-Host "Stripping invalid accounts." -ForegroundColor yellow
            $Global:UserArrayValid = $Global:UserArray | Where-Object {$_.Account_Valid -ne $false}          

}

Function UserReport{
                
Write-Host "Please select email account(s) to report. (single or comma seperated)" -NoNewline
$BreachUsers = (Read-Host " ").split(',') |% {$_.trim()}                
    Foreach($UserObject in $BreachUsers){
                    Write-Progress -Activity "Checking Account Stats" -Status "User:$UserObject" -PercentComplete (($BreachUsers.indexof($UserObject)/$BreachUsers.Count)*100)
                    $Alias = $UserObject.split('@')

                    If($Pwnd.BreachSearchResults.Alias -eq $Alias[0]){
                    $Account = $Pwnd.BreachSearchResults[$Pwnd.BreachSearchResults.Alias.IndexOf($Alias[0])]
                    $UserAccount = "$($Account.Alias)@$($Account.DomainName)"
                    $ADUserInfo = Get-aduser -Filter {mail -like $UserAccount} -Properties *

                    sleep -Milliseconds 50            
                    Foreach($Breach in $Account.Breaches){
                            $UserArrayO = "" | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Department,AD_Office,AD_Company,AD_Enabled,AD_LastPssRst;
                            $UserArrayO.Account = $UserAccount
                            $UserArrayO.BreachName = $Breach.Title
                            $UserArrayO.BreachType = "Breach"
                            $UserArrayO.BreachDate = if($Breach.BreachDate){[DateTime]$Breach.BreachDate}
                            If($ADUserInfo.SAMAccountName -ne $null){
                                $UserArrayO.AD_UserID = $ADUserInfo.SAMAccountName
                                $UserArrayO.AD_Department = $ADUserInfo.department
                                $UserArrayO.AD_Office = $ADUserInfo.office
                                $UserArrayO.AD_Company = $ADUserInfo.company
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.AD_LastPssRst = $ADUserInfo.PasswordLastSet
                             }
                            Else {
                                $UserArrayO.AD_UserID = "AD Account not found"
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.Account_At_Risk = $False
                                $UserArrayO.Account_Valid = $False
                                }

                            If($ADUserInfo.SAMAccountName -ne $null -and $ADUserInfo.enabled -eq $True){
                                $UserArrayO.Account_Valid = $True                    
                                
                                If($ADUserInfo.PasswordLastSet -lt $Breach.BreachDate){
                                    $UserArrayO.Account_At_Risk = $True
                                }
                                Else{
                                    $UserArrayO.Account_At_Risk = $false
                                }
                                }
                            Else{
                                $UserArrayO.Account_Valid = $False
                                }          
                          $Global:UserArray += $UserArrayO
                        }
                    }

                    If($Pwnd.PasteSearchResults.Alias -eq $Alias[0]){
                    $Account = $Pwnd.PasteSearchResults[$Pwnd.PasteSearchResults.Alias.IndexOf($Alias[0])]
                    $UserAccount = "$($Account.Alias)@$($Account.DomainName)"
                    $ADUserInfo = Get-aduser -Filter {mail -like $UserAccount} -Properties *

                    sleep -Milliseconds 50            
                    Foreach($Breach in $Account.Pastes){
                            $UserArrayO = "" | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Department,AD_Office,AD_Company,AD_Enabled,AD_LastPssRst;
                            $UserArrayO.Account = $UserAccount
                            $UserArrayO.BreachName = "$($Breach.Title) - $($Breach.Id) - $($Breach.Title) "
                            $UserArrayO.BreachType = "Paste"
                            $UserArrayO.BreachDate = if($Breach.Date){[DateTime]$Breach.Date}
                            If($ADUserInfo.SAMAccountName -ne $null){
                                $UserArrayO.AD_UserID = $ADUserInfo.SAMAccountName
                                $UserArrayO.AD_Department = $ADUserInfo.department
                                $UserArrayO.AD_Office = $ADUserInfo.office
                                $UserArrayO.AD_Company = $ADUserInfo.company
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.AD_LastPssRst = $ADUserInfo.PasswordLastSet
                             }
                            Else {
                                $UserArrayO.AD_UserID = "AD Account not found"
                                $UserArrayO.AD_Enabled = $ADUserInfo.enabled
                                $UserArrayO.Account_At_Risk = $False
                                $UserArrayO.Account_Valid = $False
                                }

                            If($ADUserInfo.SAMAccountName -ne $null -and $ADUserInfo.enabled -eq $True){
                                $UserArrayO.Account_Valid = $True                        
                                
                                If($ADUserInfo.PasswordLastSet -lt $Breach.Date){
                                    $UserArrayO.Account_At_Risk = $True
                                }
                                Else{
                                    $UserArrayO.Account_At_Risk = $false
                                }
                                }
                            Else{
                                $UserArrayO.Account_Valid = $False
                                }          
                          $Global:UserArray += $UserArrayO
                        }
                    }

                  }
            Write-Progress -Activity "Checking account stats" -Completed          
            Write-Host "Breach reporting complete." -ForegroundColor Green 
            Write-Host "Stripping invalid accounts." -ForegroundColor yellow
            $Global:UserArrayValid = $Global:UserArray | Where-Object {$_.Account_Valid -ne $false}                                              
         
}

Function Output{
    $BreachN = $Global:UserArray | Select BreachName|  Sort-Object -Unique -Property BreachName
    $BreachT = $Global:UserArray | Select BreachType|  Sort-Object -Unique -Property BreachType
 
    IF($BreachN.BreachName.Count -eq 1 -and $BreachT.BreachType -eq "Breach"){
        $BreachDesc = $Titles[$Titles.Title.IndexOf($BreachN.BreachName)].Description -replace("'"),("")           
        $BreachReport = $BreachN.BreachName
        $HTMLReport = $Global:UserArrayValid | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Enabled,AD_LastPssRst| Sort-Object -Property Account -Descending | ConvertTo-Html -Head $TableHeader 
    }
    ElseIF($BreachN.BreachName.Count -eq 1 -and $BreachT.BreachType -eq "Paste"){
        $BreachDesc = "Data was pasted on an anonymous website: $($PasteTitles[$PasteTitles.Id.IndexOf($BreachN)].Source) with the ID/link of $($BreachN.BreachName)."
        $BreachReport = $PasteTitles[$PasteTitles.Id.IndexOf($BreachN)].Source
        $HTMLReport = $Global:UserArrayValid | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Enabled,AD_LastPssRst| Sort-Object -Property Account -Descending | ConvertTo-Html -Head $TableHeader 
    }
    Else{
        $BreachDesc = "No Description Available."
        $BreachReport = "Multiple breach/paste dumps"
        $HTMLReport = $Global:UserArrayValid | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Enabled,AD_LastPssRst| Sort-Object -Property Account -Descending | ConvertTo-Html -Head $TableHeader
    }
            Write-Host ""
            Write-Host "1) Show results." -ForegroundColor Magenta -NoNewline
            Write-Host "$tab$tab- Will show valid accounts on screen"
            Write-Host "2) Export results." -ForegroundColor Magenta -NoNewline
            Write-Host "$tab$tab- Will dump all results as a CSV to the current user's desktop."
            Write-Host "3) Email results\notice." -ForegroundColor Magenta -NoNewline
            Write-Host "$tab- Will email valid accounts in message, with all results as an attachment."
            Write-Host ""
            $GetIn = Read-Host "Show, export, email, or skip results? - Default is skip"
                Switch ($GetIn){
                1 {               
                IF($BreachN.BreachName.Count -eq 1 -and $BreachT.BreachType -eq "Breach"){                   
                    Write-Host "Below is the breach description from HIBP:" -ForegroundColor Yellow
                    Write-Host $BreachDesc
                    
                }
                $Global:UserArrayValid | Select Account,BreachName,BreachType,BreachDate,Account_Valid,Account_At_Risk,AD_UserID,AD_Enabled,AD_LastPssRst | Sort-Object -Property @{E={$_.Account};D=$false}, @{E={$_.Account_Valid};D=$true}, @{E={$_.Account_At_Risk};D=$true} | FT -AutoSize -Wrap
                }

                2{
                $Global:UserArray | Sort-Object -Property Account -Descending | Export-Csv -NoTypeInformation -Force "$DesktopPath\breached_users.csv"
                    If (Test-Path "$DesktopPath\breached_users.csv"){
                    Write-Host "Export Success" -ForegroundColor Green
                    }
                    Else {
                    Write-Host "Export Failed" -ForegroundColor Red
                    }
                }
                3{
                $Global:UserArray | Sort-Object -Property Account -Descending | Export-Csv -NoTypeInformation -Force "$env:temp\breached_users.csv"
                
                    If (Test-Path "$env:temp\breached_users.csv"){
                    Write-Host "Export Success" -ForegroundColor Green
                    }
                    Else {
                    Write-Host "Export Failed" -ForegroundColor Red
                    }

                    $EmailTo = @($EmailT)
                    Write-Host "Default Recipients: " -ForegroundColor Magenta -NoNewline 
                    Write-Host $EmailTo -ForegroundColor Yellow
                    Write-Host "Enter email address(es) here (single or comma seperated)" -ForegroundColor Magenta -NoNewline 
                                    
                    $EmailAdd = @(Read-Host " ").split(',') |% {$_.trim()}
                                
                    If ($EmailAdd -ne ""){
                        $EmailTo += $EmailAdd
                    }                                    

                    If ($EmailTo.Contains("@") -ige 0){                                                           
                        $EmailFrom = $EmailF
                        $EmailSubject = $EmailSub
                        $EmailServer = $EmailSvr                                                                           
                        $EmailBody = "$FormatStart Notice: <br />
                        <br />
                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; The $SecurityTeamName was notified that $CompanyName user data was disclosed in a recent breach identified as <em>`'$BreachReport`.'</em> On $(Get-Date -Format "MM/dd/yyyy"), we performed an analysis of the disclosed data to identify active $CompanyName user accounts included in the breach data. The following report lists active user accounts and email addresses identified in this process. As these accounts may be at risk, please assess what next steps are warranted, including user notification. <br />
                        <br />
                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <u> Description of the data breach:</u><br />$FormatEnd
                        <table style=`"margin-left:15px`"><tr><td> $FormatStart`"$BreachDesc`"$FormatEnd</td></tr></table><br />
                        <br />
                        $HTMLReport $FormatStart
                        <br />
                        For further reference the full report of all accounts is also attached.<br />                                                            
                        <br />
                        Please reply with any questions or concerns.<br />
                        <br />
                        Regards<br />
                        <br />
                        $SecurityTeamName $FormatEnd
                        "

                        $messageParameters = @{                        
                            Subject = $EmailSubject
                            Body = $EmailBody
                            From = $EmailFrom                 
                            To = $EmailTo
                            Attachments = @("$env:temp\breached_users.csv")
                            SmtpServer = $EmailServer
                        } 

                        #Send Email
                        Send-MailMessage @messageParameters -BodyAsHtml
                        Write-Host "Email sent to $EmailTo" -ForegroundColor Green 
                                        
                        #Remove the data                                            
                        Remove-Item "$env:temp\breached_users.csv" -Force                                    
                        }



                }
                Default{                           
                }
                }

}

StartMenu
