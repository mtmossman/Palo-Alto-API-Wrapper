###########################################################
## Name: PAGet.psm1
## Author: Matt Mossman
## Tested on: Windows 7 SP1 Powershell version 5.0
## Description: Powershell module for interacting with the Palo-Alto API
##
##
###########################################################

#global hashtable of requests for functions. The Numbers in brackets are placeholder for variables that are declared inside the functions that pull values from this hashtable.
$requests = @{
    "Get-PAKey" = "https://{0}/api/?type=keygen&user={1}&password={2}"
    "Get-DeviceList" = "https://{0}/api/?type=config&action=get&xpath=/config/devices"
    "Get-CandidateConfig" = "https://{0}/api/?type=export&category=configuration"
    "Get-UserList" = "https://{0}/api/?type=config&action=get&xpath=/config/mgt-config/users"
    "Get-AuthProfileList" = "https://{0}/api/?type=config&action=get&xpath=/config/shared/authentication-profile"
    "Get-SyslogServerList" = "https://{0}/api/?type=config&action=get&xpath=/config/shared/log-settings/syslog"
    "Get-SnmpServerList" = "https://{0}/api/?type=config&action=get&xpath=/config/shared/log-settings/snmptrap"
    "Get-PasswordProfiles" = "https://{0}/api/?type=config&action=get&xpath=/config/mgt-config/password-profile"
    "Get-Hostname" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/hostname"
    "Get-HostnameInSyslog" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/setting/management/hostname-type-in-syslog"
    "Get-LogForwardingProfileList" = "https://{0}/api/?type=config&action=get&xpath=/config/shared/log-settings/profiles"
    "Get-NtpServerList" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/ntp-servers"
    "Get-DnsServerList" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/dns-setting/servers"
    "Get-UpdateServer" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/update-server"
    "Get-ProxyServerAddress" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/secure-proxy-server"
    "Get-ProxyServerPort" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/member[@name='secure-proxy-port']"
    "Get-SystemConfig" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system"
    "Get-ProxyUserName" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/secure-proxy-user"
    "Get-ProxyPassword" = "https://{0}/api/?type=config&action=get&xpath=/config/devices/entry[@name='{1}']/deviceconfig/system/secure-proxy-password"
}

#Ignore cert failure, this must remain global. Palo-Alto's self-signed certificate will fail the cert check on the current version of powershell.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} 


#Send Web Request to Palo-Alto and return the result to the calling function. Requires the request and apikey already formatted 
function Send-Request
{
    param(
        [Parameter(Mandatory=$true, Position=0)]$uri,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey
         )
        
    Try
    {
        $request_object = New-object System.Net.WebClient
        $request = "$uri&key=$apikey"
        $response = $request_object.DownloadString($request)
        $xml_response = [xml] $response
        return $xml_response
    }

    Catch
    {
        Write-Host "Error in Send-Request function. This error typically occurs when the calling function passes an improperly formatted request."
    }
}


#This function will take the username, password, and IP of the target Palo-Alto and return an API key that can be used for other functions.
#the $raw switch arugment will return the raw object
function Get-PAKey
{
<#
.SYNOPSIS
    Used to attain API key from Palo-Alto.
.DESCRIPTION
    Attain API key from Palo-Alto firewall. This API key will be required for other functions in this module.
    It is recommended that you used variables for the password argument to avoid complications in the event the password uses special characters
    
    EXAMPLE:
        $firewall = "192.168.1.10"
        $user = "admin"
        $password = "test123$"
    
        $api_key = $apikey = Get-PAKey -ip $firewall -user $user -password $password
.EXAMPLE
    $api_key = Get-PAKey -ip 192.168.1.10 -user admin -password Password1234!
.EXAMPLE
    $raw_api_key = Get-PAKey -ip $firewall -user $user -password $password -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER user
    Takes username of login account that will be used
.PARAMETER password
    Takes corresponding password for the username
.PARAMETER raw
    This switch will return the raw xml object not yet parsed for the API key

#>


    param(
        [Parameter(Mandatory=$true, Position=0)]$ip, 
        [Parameter(Mandatory=$true, Position=1)]$user, 
        [Parameter(Mandatory=$true, Position=2)]$password,
        [Parameter(Mandatory=$false,Position=3)][switch]$raw
     )

    Try
    {
        $object = New-Object System.Net.WebClient
        $key_request = $requests.Get_Item("Get-PAKey") -f $ip, $user, $password
        $sent_request = $object.downloadstring($key_request)
        $xml_response = [xml] $sent_request
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $xml_response
        }

        #Return parsed object if switch statement is not present
        else
        {
            return $xml_response.response.result.key
        }
    }

    Catch
    {
        Write-host "Failure when sending request for api key"
    }
}

#Returns Config as an xml object
#$returned_object.save("test.xml") will save the config to the current directory as "test.xml"
function Get-CandidateConfig
{
<#
.SYNOPSIS
    Used to pull the Candidate Config from the target firewall.
.DESCRIPTION
    Use this function to remotely pull firewall configurations to current working directory. Saving the configuration to specific file paths is not yet supported.
    
    EXAMPLE:    
       Get-CandidateConfig -ip 192.168.1.10 -apikey $api

.EXAMPLE
    $config = Get-CandidateConfig -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER file
    Takes a file name to save the Configuration
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml object without saving it to the filesystem
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)]$file = "Candidate-Config.xml",
        [Parameter(Mandatory=$false,Position=3)][switch]$raw
     
         )
    Try
    {
        $request = $requests.Get_Item("Get-CandidateConfig") -f $ip
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }
        #Return parsed object if switch statement is not present
        else
        {
            $response.save("$pwd\$file")
        }

     }

    Catch
    {
        Write-host "Error inside the Get-CandidateConfig function"
    }
}

#Return list of devices (helpful with other functions that require a devicename)
#This function has no need for a -raw switch argument.
function Get-DeviceList
{
<#
.SYNOPSIS
    Used to get a list of device names from a target firewall
.DESCRIPTION
    Default hostname for a Palo-Alto is localhost.localhost, this function can be used to verify either that the devices is using the default value or a different value
    
    EXAMPLE:    
       Get-DeviceList 192.168.1.10 $api

.EXAMPLE
    $devices = Get-DeviceList -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for device names.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
    Try
    {
        $request = $requests.Get_Item("Get-DeviceList") -f $ip
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $device_array = @()
            $response.response.result.devices | foreach-object {$device_array += $_.entry.name}
            return $device_array
        }
     }
        Catch
        {
            Write-host "Error in Get-DeviceList function"
        }
}
#Returns list of users on Palo-Alto device
#$user_array is created as a null array and appended to in the foreach-object loop.
#the $raw switch argument returns the raw object
function Get-UserList
{
<#
.SYNOPSIS
    Used to get a list of device names from a target firewall
.DESCRIPTION
    Get a list of Users from target firewall    
    
    EXAMPLE:    
       Get-UserList 10.128.8.187 $api

.EXAMPLE
    $users = Get-UserList -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for User names.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
   Try
   {

        $request = $requests.Get_Item("Get-UserList") -f $ip
        $response = Send-Request $request $apikey
   
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $user_array = @()
            $response.response.result.users | Foreach-Object {$user_array += $_.entry.name}
            return $user_array
        }
   }
   
   Catch
   {
        Write-Host "Error in Get-UserList function"
   }
}

#Returns array of authentication profiles on the Palo-Alto
#$auth_profile_array is created as a null array and appended to in the foreach-object loop.
#the $raw switch argument returns the raw object
function Get-AuthProfileList
{
<#
.SYNOPSIS
    Used to get a list of Authentication profiles from a target firewall
.DESCRIPTION
    Get a list of Authentication Profiles from target firewall    
    
    EXAMPLE:    
       Get-AuthProfiles 10.128.8.187 $api

.EXAMPLE
    $AuthProfiles = Get-AuthProfiles -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for Authentication Profiles.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
    Try
    {
        $request = $requests.Get_Item("Get-AuthProfileList") -f $ip
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $auth_profile_array = @()
            $response.response.result.'authentication-profile' | foreach-object {$auth_profile_array += $_.entry.name}
            return $auth_profile_array
        }
    }
    
    Catch
    {
        Write-Host "Error in GetAuthProfileList function"
    }
}

#Returns array of syslog servers
#$syslog_servers is created as a null array and appended to in the foreach-object loop
#the $raw switch argument returns the raw object
function Get-SyslogServerList
{
<#
.SYNOPSIS
    Used to get a list of Syslog Servers from a target firewall
.DESCRIPTION
    Get a list of Syslog Servers from target firewall    
    
    EXAMPLE:    
       Get-AuthProfiles 10.128.8.187 $api

.EXAMPLE
    $SyslogServers = Get-SyslogServersList -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for syslog servers.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
    
    Try
    {
        $request = $requests.Get_Item("Get-SyslogServerList") -f $ip
        $response = Send-Request $request $apikey
    
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $syslog_servers = @()
            $response.response.result.syslog | foreach-object {$syslog_servers += $_.entry.name}
            return $syslog_servers
        }
    }

    Catch
    {
        Write-Host "Error in Get-SyslogServerList Function"
    }
}

#Returns array of snmptrap servers
#$snmp_servers is created as a null array and appended to in the foreach-object loop
#the $raw switch argument returns the raw object
function Get-SnmpServerList
{
<#
.SYNOPSIS
    Used to get a list of SNMP Servers from a target firewall
.DESCRIPTION
    Get a list of SNMP Servers from target firewall    
    
    EXAMPLE:    
       Get-SmnpServerList 10.128.8.187 $api

.EXAMPLE
    $SnmpServers = Get-SnmpServersList -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for snmp servers.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
    Try
    {
        $request = $requests.Get_Item("Get-SnmpServerList") -f $ip
        $response = Send-Request $request $apikey
    
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $snmp_servers = @()
            $response.response.result.snmptrap | foreach-object {$snmp_servers += $_.entry.name}
            return $snmp_servers
        }
    }
    
    Catch
    {
        Write-host "Error in Get-SnmpServerList function"
    }
}

#Returns list of log forwarding profiles
#the $raw switch argument returns the raw object
function Get-LogForwardingProfileList
{
<#
.SYNOPSIS
    Used to get a list of Log Forwarding Profiles from a target firewall
.DESCRIPTION
    Get a list of Log Forwarding Profiles from target firewall    
    
    EXAMPLE:    
       Get-LogForwardingProfileList 10.128.8.187 $api

.EXAMPLE
    $LogForwardingProfileList = Get-LogForwardingProfileList -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for Log Forwarding Profiles.
#>
     param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
     Try
     {
        $request = $requests.Get_Item("Get-LogForwardingProfileList") -f $ip
        $response = Send-Request $request $apikey
     
        #Check switch statement and return raw object if true
        if($raw)
        {
           return $response
        }
     
        #Return parsed object if switch statement is not present
        else
        {
           $log_forwarding_profile_array = @()
           $response.response.result.profiles | foreach-object {$log_forwarding_profile_array += $_.entry.name}
           return $log_forwarding_profile_array
        }
     }

     Catch
     {
        Write-Host "Error in Get-LogForwardingProfileList function"
     }
}

#Returns list of Password Profiles
#the $raw switch argument returns the raw object
function Get-PasswordProfileList
{
<#
.SYNOPSIS
    Used to get a list of Password Profiles from a target firewall
.DESCRIPTION
    Get a list of Password Profiles from target firewall    
    
    EXAMPLE:    
       Get-PasswordProfilesList 10.128.8.187 $api

.EXAMPLE
    $PasswordProfiles = Get-LogForwardingProfileList -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for Password Profiles.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)][switch]$raw
         )
    Try
    {
        $request = $requests.Get_Item("Get-PasswordProfiles") -f $ip
        $response = Send-Request $request $apikey

        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $password_profile_array = @()
            $response.response.result.'password-profile' | foreach-object {$password_profile_array += $_.entry.name}
            return $password_profile_array
        }
   }

   Catch
   {
        Write-Host "Error in Get-PasswordProfileList function"
   }
}

#Returns Palo-Alto hostname. (@name is default set to 'localhost.localdomain' but can be changed with -device argument)
#The $raw switch argument returns the raw object
#In the event you define a devicename, if the returned object is null it typically means the supplied device name is invalid
function Get-HostName
{
<#
.SYNOPSIS
    Used to get the Hostname from a target firewall
.DESCRIPTION
    Get the HostName of the target firewall    
    
    EXAMPLE:    
       Get-HostName 10.128.8.187 $api

.EXAMPLE
    $Hostname = Get-HostName -ip 192.168.1.10 -apikey $api -raw
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER raw
    This switch will return the raw xml before being parsed for the Hostname.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
        [Parameter(Mandatory=$false,Position=3)][switch]$raw
         )
    Try
    {
        $request = $requests.Get_Item("Get-Hostname") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }
    
        #Return parsed object if switch statement is not present
        else
        {
            return $response.response.result.hostname
        }
    }
    Catch
    {
        Write-host "Error in Get-HostName function"
    }
}

#Returns the value of the 'Send HOSTNAME in Syslog' field (@name is default set to 'localhost.localdomain' but can be changed with the -device argument)
#The $raw switch argument returns the raw object
#In the event you define a devicename, if the returned object is null it typically means the supplied device name is invalid
function Get-HostnameInSyslog
{
<#
.SYNOPSIS
    Used to get the 'Syslog HOSTNAME Format' field from the Logging and Reporting Settings Pane in Palo-Alto
.DESCRIPTION
    Get the 'Syslog HOSTNAME Format' field of the target firewall    
    
    EXAMPLE:    
       Get-HostnameInSyslog 10.128.8.187 $api

.EXAMPLE
    $HostnameInSyslog = Get-HostNameInSYslog -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-HostnameInSyslog -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for the HOSTNAME field.
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]$ip,
        [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
        [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
        [Parameter(Mandatory=$false,Position=3)][switch]$raw
         )
    Try
    {
        $request = $requests.Get_Item("Get-HostnameInSyslog") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            return $response.response.result.'hostname-type-in-syslog'
        }
    }

    Catch
    {
        Write-Host "Error in Get-HostnameInSyslog function"
    }
}

#Returns list of addresses for the primary and secondary ntp servers  (@name is default set to 'localhost.localdomain' but can be changed with the -device argument)
#the $raw switch argument returns the raw object
#In the event you define a devicename, if the returned object is null it typically means the supplied device name is invalid
function Get-NtpServerList
{
<#
.SYNOPSIS
    Used to get the primary and secondary NTP servers from Palo-Alto firewalls
.DESCRIPTION
    Get the NTP servers used by the target firewall    
    
    EXAMPLE:    
       Get-NtpServerList 10.128.8.187 $api

.EXAMPLE
    $Get-NtpServerList = Get-NtpServerList -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-NtpServerList -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for NTP servers.
#>
    param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
         ) 
    Try
    {
        $request = $requests.Get_Item("Get-NtpServerList") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }
    
        #Return parsed object if switch statement is not present
        else
        {
            $ntp_server_array = @()
            $ntp_server_array += $response.response.result.'ntp-servers'.'primary-ntp-server'.'ntp-server-address'
            $ntp_server_array += $response.response.result.'ntp-servers'.'secondary-ntp-server'.'ntp-server-address'
            return $ntp_server_array
        }
    }

    Catch
    {
        Write-host "Error in Get-NtpServerList function"
    }
}

function Get-DnsServerList
{
<#
.SYNOPSIS
    Used to get the primary and secondary DNS servers from Palo-Alto firewalls
.DESCRIPTION
    Get the DNS servers used by the target firewall    
    
    EXAMPLE:    
       Get-DnsServerList 10.128.8.187 $api

.EXAMPLE
    $Get-DnsServerList = Get-DnsServerList -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-DnsServerList -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for DNS servers.
#>
     param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
          )
    Try
    {
        $request = $requests.Get_Item("Get-DnsServerList") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            $dns_server_array = @()
            $dns_server_array += $response.response.result.servers.primary
            $dns_server_array += $response.response.result.servers.secondary.'#text'
            return $dns_server_array
        }
    }

    Catch
    {
        Write-host "Error in Get-DnsServerList function"
    }
}

function Get-UpdateServer
{
<#
.SYNOPSIS
    Used to get the Update Server that checks for software, signature, AppID, etc updates from Palo-Alto
.DESCRIPTION
    Get the Update Server used by the target firewall    
    
    EXAMPLE:    
       Get-UpdateServer 10.128.8.187 $api

.EXAMPLE
    $UpdateServer = Get-UpdateServer -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-UpdateServer -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for the update server.
#>
    param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
        )

    Try
    {
        $request = $requests.Get_Item("Get-UpdateServer") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            return $response.response.result.'update-server'.'#text'
        }
    }
    
    Catch
    {
        Write-Host "Error in Get-UpdateServer function"
    }
}

function Get-ProxyServerAddress
{
<#
.SYNOPSIS
    Used to get the IP address of the proxy server from the target Palo-Alto firewall
.DESCRIPTION
    Get the address of the proxy server used by the target firewall    
    
    EXAMPLE:    
       Get-ProxyServerAddress 10.128.8.187 $api

.EXAMPLE
    $Proxy_Address = Get-ProxyServerAddress -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-ProxyServerAddress -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for the proxy server address.
#>
    param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
        )

    Try
    {
        $request = $requests.Get_Item("Get-ProxyServerAddress") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            return $response.response.result.'secure-proxy-server'
        }
    }

    Catch
    {
        Write-Host "Error in the Get-ProxyServerAddress function"
    }

}

function Get-ProxyServerPort
{
<#
.SYNOPSIS
    Used to get the port used by the proxy server from the target Palo-Alto firewall
.DESCRIPTION
    Get the port of the proxy server used by the target firewall    
    
    EXAMPLE:    
       Get-ProxyServerPort 10.128.8.187 $api

.EXAMPLE
    $Proxy_Port = Get-ProxyServerPort -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-ProxyServerPort -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for the proxy server port.
#>
    param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
        )
    
    Try
    {
        $request = $requests.Get_Item("Get-SystemConfig") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }

        #Return parsed object if switch statement is not present
        else
        {
            return $response.response.result.system.'secure-proxy-port'
        }
    }

    Catch
    {
        Write-Host "Error in the Get-ProxyServerPort function"
    }

}

function Get-ProxyUserName
{
<#
.SYNOPSIS
    Used to get the username used to authenticate to the proxy server from the target Palo-Alto firewall
.DESCRIPTION
    Get the username for the proxy server used by the target firewall    
    
    EXAMPLE:    
       Get-ProxyUser 10.128.8.187 $api

.EXAMPLE
    $Proxy_User = Get-ProxyUser -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-ProxyUser -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for the username for the proxy.
#>
    param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
        )
    
    Try
    {
        $request = $requests.Get_Item("Get-ProxyUserName") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }
        
        else
        {
            return $response.response.result.'secure-proxy-user'.'#text'
        }
    }
    
    #Return parsed object if switch statement is not present
    Catch
    {
        Write-host "Error in the Get-ProxyUserName function"
    }
}

function Get-ProxyPassword
{
<#
.SYNOPSIS
    Used to get the password hash used to authenticate to the proxy server from the target Palo-Alto firewall
.DESCRIPTION
    Get the password hash for the proxy server used by the target firewall    
    
    EXAMPLE:    
       Get-ProxyPassword 10.128.8.187 $api

.EXAMPLE
    $Proxy_Password = Get-ProxyPassword -ip 192.168.1.10 -apikey $api -raw
.EXAMPLE
    Get-ProxyPassword -ip 10.128.8.187 -apikey $api -device localhost.localdomain
.PARAMETER ip
    Takes IP address of Palo-Alto firewall as a string
.PARAMETER apikey
    Takes apikey variable that is used to authenticate to the firewall
.PARAMETER device
    Takes the devicename of the firewall. Default value is localhost.localdomain
.PARAMETER raw
    This switch will return the raw xml before being parsed for the password for the proxy.
#>
    param(
       [Parameter(Mandatory=$true, Position=0)]$ip,
       [Parameter(Mandatory=$true, Position=1, ValuefromPipeLine = $true)]$apikey,
       [Parameter(Mandatory=$false,Position=2)]$device = "localhost.localdomain",
       [Parameter(Mandatory=$false,Position=3)][switch]$raw
        )
    
    Try
    {
        $request = $requests.Get_Item("Get-ProxyPassword") -f $ip, $device
        $response = Send-Request $request $apikey
        
        #Check switch statement and return raw object if true
        if($raw)
        {
            return $response
        }
        
        else
        {
            return $response.response.result.'secure-proxy-password'.'#text'
        }
    }
    
    #Return parsed object if switch statement is not present
    Catch
    {
        Write-host "Error in the Get-ProxyPassword function"
    }
}