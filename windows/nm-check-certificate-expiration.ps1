#==========================================================
# LANG : Powershell
# NAME : nm-check-certificate-expiration.ps1
# AUTHOR : Patrick Ogenstad
# VERSION : 1.0
# DATE : 2014-02-09
# Description : Checks to see a certificate is about to
# expire.
#
# Information: The Script is part of Nelmon (NetworkLore
# Monitoring Pack for Nagios)
# http://networklore.com/nelmon/
#
# Guidelines and updates:
# http://networklore.com/windows-certificate-expiration/
#
# Feedback: Please send feedback:
# http://networklore.com/contact/
#
# Changelog:
# 2015-11-12 - RI - Changed default warning from 10 to 30, 
#					critical from 20 to 60, updated text 
#					outputs to include status and perf
# 2016-06-09 - RI - Added CRL checks and outputs
# 2017-10-23 - RI - Changed Certdir to parameter and added
#                   support for multiple stores
#
#==========================================================
#==========================================================

Param(
    [string[]]$CERTDIR = "Cert:\LocalMachine\My",
    [int]$critical = 30,
    [switch]$help,
    [int]$warning = 60
)

$scriptversion = "1.2"



$bReturnOK = $TRUE
$bReturnCritical = $FALSE
$bReturnWarning = $FALSE
$returnStateOK = 0
$returnStateWarning = 1
$returnStateCritical = 2
$returnStateUnknown = 3
$nWarning = $warning
$nCritical = $critical
$strRemainStatus = ""
$strGlobalStatus = ""
$strGlobalPerf = ""
$intWarn = 0
$intCrit = 0
$intOk = 0
$crlCriticalCount = 0
$crlWarningCount = 0
$crlOkCount = 0

$dtCurrent = Get-Date

$strCritical = ""
$strWarning = ""

if ($help) {
    Write-Output ""
    Write-Output "---------------------------------------------"
    Write-Output "nm-check-certificate-expiration.ps1 v.$scriptversion"
    Write-Output "---------------------------------------------"
    Write-Output ""
    Write-Output "Options:"
    Write-Output "-certdir (string/array of strings, path to cert store/stores)"
    Write-Output "-c or -critical (number)"
    Write-Output "-h or -help display help"
    Write-Output "-w or -warning (number)"
    Write-Output "" 
    Write-Output "Example:"
    Write-Output ".\nm-check-certificate-expiration.ps1 -c 4 -w 10"
    Write-Output ""
    Write-Output "For more information visit:"
    Write-Output "http://networklore.com/nelmon/"
    Write-Output "http://networklore.com/windows-certificate-expiration/"
    Write-Output ""
    exit $returnStateUnknown
} 


$objCertificates = Get-Childitem $CERTDIR

if (-Not $objCertificates) { 
    Write-Output "No Certificates Found"
    exit $returnStateOK
}

foreach ($objCertificate in $objCertificates) {
    $dtRemain = $objCertificate.NotAfter - $dtCurrent
    $nRemainDays = $dtRemain.Days
    $nMaxDays = ($objCertificate.NotAfter - $objCertificate.NotBefore).days
    # Check if http crl's are reachable
    $crlOverallState = $returnStateOK
    $crlOverallStatus = "OK"
    $crlHttpStatus = "No HTTP crl available "
    $crlLDAPStatus = "No LDAP crl available"
    $urls = $objCertificate.extensions|? {$_.oid.value -eq "2.5.29.31"}| % {$_.format(1).split()|? {$_ -like "URL=*"}}
    $crlPathCount = $urls.count
    if ($crlPathCount -eq 0) {$crlOverallStatus = "No crl available"}
    $urls| % {
        $url = $_
        switch ($_.substring(4, 4)) {
            "http" {
                $crlHttpStatus = "HTTP crl reachable (OK)"
                $crlHttpCount += 1
                $httpCRL = invoke-webrequest $url.substring(4)
                if ($httpCRL.statusCode -ne "200") {
                    $crlFailed += 1
                    $crlHttpStatus = "CRL not available over HTTP, server returned: $($httpCRL.statuscode)($($httpCRL.statusDescription))"
                }
            }
            "ldap" {
                $crlLDAPStatus = "LDAP crl reachable (OK)"
                $crlLdapCount += 1
                $ldapPath = $url.substring(4) -replace "ldap:///", "" -replace "\?[a-zA-Z=?]*", ""
                $ldapPath = [system.web.httputility]::UrlDecode($ldapPath)
                try {
                    If (! [system.directoryservices.directoryentry]::exists("LDAP://" + $ldapPath)) {						
                        $crlOverallState = $returnStateCritical
                        $crlLDAPStatus = "LDAP path does not exist: $ldapPath"
                        $crlFailed += 1
                    } 
                }
                catch {
                    $crlFailed += 1						
                    $crlLDAPStatus = "Error while connecting to LDAP: $ldapPath"
                }
            }
        }
        if ($crlPathCount -eq $crlFailed) {
            $crlOverallState = $returnStateCritical
            $crlOverallStatus = "CRITICAL"
            $crlCriticalCount += 1
        }
        elseif ($crlFailed -gt 0) {
            $crlOverallState = $returnStateWarning
            $crlOverallStatus = "WARNING"
            $crlWarningCount += 1
        }
        else {
            $crlOkCount += 1
        }
    }
    if ($nRemainDays -lt 0) {
        $strCritical = $strCritical + "EXPIRED $($objCertificate.Subject)($($objCertificate.Thumbprint)) expired $($objCertificate.NotAfter.ToString())`n"
        $strRemainStatus = "Expired"
        $intCrit += 1
    }
    Elseif ( $nRemainDays -lt $nCritical) {
        $strCritical = $strCritical + "Critical $($objCertificate.Subject)($($objCertificate.Thumbprint)) expires $($objCertificate.NotAfter.ToString())`n"
        $strRemainStatus = "Critical"
        $intCrit += 1
    }
    Elseif ( $nRemainDays -lt $nWarning) {
        $strWarning = $strWarning + "Warning $($objCertificate.Subject)($($objCertificate.Thumbprint)) expires $($objCertificate.NotAfter.ToString())`n"
        $strRemainStatus = "Warning"
        $intWarn += 1
    }
    Else {
        $strRemainStatus = "OK"
        $intOk += 1
    }

    if (@("Expired", "Critical") -contains $strRemainStatus -or $crlOverallState -eq $returnStateCritical) {
        $bReturnCritical = $true
    }
    elseif (@("Warning") -contains $strRemainStatus -or $crlOverallState -eq $returnStateWarning) {
        $bReturnWarning = $true
    }
    else {
        $bReturnOK = $true
    }
    $strGlobalMessage += "$($objCertificate.thumbprint): $($strRemainStatus.toUpper())`n`tCRL($crlPathCount): $crlOverallStatus"
    if ($crlHttpCount -gt 0 -and $crlPathCount -gt 0) {$strGlobalMessage += "`n`t $crlHttpStatus"}
    if ($crlLdapCount -gt 0 -and $crlPathCount -gt 0) {$strGlobalMessage += "`n`t $crlLDAPStatus"}
    $strGlobalMessage += "`n"
    $strGlobalPerf += "'$($objCertificate.thumbprint)'=$($nMaxDays-$nRemainDays);$($nMaxDays-$nWarning);$($nMaxDays-$nCritical);0;$nMaxDays "
}


$strGlobalStatus = "Time remaining: $intOk Ok, $intWarn Warn, $intCrit Crit`nCRLs: $crlOkCount Ok, $crlWarningCount Warn, $crlCriticalCount Crit"
write-output "$strGlobalStatus `n$strGlobalMessage | $strGlobalPerf"
if ($bReturnCritical) {
    exit $returnStateCritical
}
elseif ($bReturnWarning) {
    exit $returnStateWarning
}
else {
    exit $returnStateOK
}
