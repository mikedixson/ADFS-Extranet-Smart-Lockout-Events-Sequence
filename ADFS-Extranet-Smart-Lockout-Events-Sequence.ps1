#Note this is not my own work but the work of Sergii Cherkashyn
#Full Credit to: https://s4erka.wordpress.com/2018/11/09/powershell-script-to-collect-adfs-extranet-smart-lockout-events-sequence/
#I'm merely posting here for ease of modification going forward

$events = Get-WinEvent -MaxEvents 2000 -FilterHashtable @{Logname='Security';Id=1203,1210}
$events2 = ($events | select ID, Message,TimeCreated -ExpandProperty Message)
$info = @()
 
$events2 | foreach {
 
$IpAddresses = $null
$UserId = $null
$BadCount = $null
 
    $IpStart = $_.Message.IndexOf("<IpAddress>")
    $IpEnd = $_.Message.IndexOf("</IpAddress>")
    $IpAddresses = $_.Message.Substring($IpStart+11,($IpEnd-$IpStart-11))
 
    $UserIdStart = $_.Message.IndexOf("<UserId>")
    $UserIdEnd = $_.Message.IndexOf("</UserId>")
    $UserId = $_.Message.Substring($UserIdStart+8,($UserIdEnd-$UserIdStart-8))
     
 if ($_.Id -like 1210) 
    {
    $BadCountStart = $_.Message.IndexOf("<CurrentBadPasswordCount>")
    $BadCountEnd = $_.Message.IndexOf("</CurrentBadPasswordCount>")
    $BadCount = $_.Message.Substring($BadCountStart+25,($BadCountEnd-$BadCountStart-25))
    }
    else {$BadCount = $null}
 
$Fail = New-object -TypeName PSObject
add-member -inputobject $Fail -membertype noteproperty -name "EventID" -value $_.Id
add-member -inputobject $Fail -membertype noteproperty -name "TimeStamp" -value $_.TimeCreated
add-member -inputobject $Fail -membertype noteproperty -name "IPaddress" -value $IpAddresses
add-member -inputobject $Fail -membertype noteproperty -name "User ID" -value $UserId
add-member -inputobject $Fail -membertype noteproperty -name "BadCount" -value $BadCount
 
$info +=$Fail
}
$info | FT
