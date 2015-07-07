configuration RaxUser
{
    param
    (
        [string[]]$NodeName = [system.environment]::MachineName,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)]$Password
    ) 
 
 
 

    Node $NodeName
    {
 
        User LocalAdmin {
            UserName = $support
            Description = 'Our new local admin'
            Ensure = 'Present'
            FullName = 'Rax Support'
            Password = $Password
            PasswordChangeRequired = $false
            PasswordNeverExpires = $true
            
        }

        Group AddToAdmin{
            GroupName='Administrators'
            DependsOn= '[User]LocalAdmin'
            Ensure= 'Present'
            MembersToInclude=$support
 
        }
 
    }
}
 
$configData = 'a'
 
$configData = @{
                AllNodes = @(
                              @{
                                 NodeName = [system.environment]::MachineName;
                                 PSDscAllowPlainTextPassword = $true
                                    }
                    )
               }

$secpassword = "Test1234!" | ConvertTo-SecureString -AsPlainText -Force 
$secusername = "RAXSupport"
$hostname = [system.environment]::MachineName
$date = get-date -Format hhmmss
$support = $secusername+$date

$mycreds = New-Object System.Management.Automation.PSCredential ($support, $secpassword)
 
RaxUser -Password $mycreds -UserName $support -ConfigurationData $configData
 
Start-DscConfiguration -ComputerName $hostname -Wait -Force -Verbose -path C:\Scripts\RaxUser
