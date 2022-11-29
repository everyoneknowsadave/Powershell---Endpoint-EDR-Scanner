#Written by DPEH
#Powershell Malware Scanner
#Version 0.5

clear
$customscanpath = "C:\Users\"
$customscanpath = "C:\Windows\temp\"
$customscanpath = "C:\Users\DavidHazelden\"
$customscanpath = "C:\Users\Public\"
$customscanpath = "C:\Users\Windows\"
$customscanpath = "C:\Users\DavidHazelden\Desktop\malware-testing"
$customscanpath = "C:\Users\DavidHazelden\Desktop\Screenshots"

$base_path_evidence = 'C:\temp\'
$daysX = 2
$apimaxcalls = 1

#Write-Host $base_path_evidence

#make folder for evidence exports
$evidencefoldername1 = $(((get-date).ToUniversalTime()).ToString("yyyy-MM-dd-T-HH"))
$filenamedate = $(((get-date).ToUniversalTime()).ToString("yyyyMMddTHHmmssZ"))

Write-Host "Evidence Date:-" $evidencefoldername1

$evidenceoutput = $($base_path_evidence + "evidence-$evidencefoldername1" + "\")
Write-host "Saving Evidence to:- $evidenceoutput"

If(!(test-path -PathType container $evidenceoutput))
{
      New-Item -ItemType "Directory" -Path $evidenceoutput | Out-Null
      Write-Output "Making directory $evidenceoutput"

}


if(Test-Path ".\vtotalapi.txt" -PathType Leaf)
{
    $vtotal_apikey = Get-Content -Path ".\vtotalapi.txt"
    Write-Warning "Custom Virus Total Key Found!"
    $bool_vtotalscan = $true
}
else
{
    #$vtotal_apikey = ""
    $bool_vtotalscan = $false
}

if(Test-Path ".\scan_for_hashes_custom_list.txt" -PathType Leaf)
{
    $txtfile_scan_for_hashes_custom_list = Get-Content -Path ".\scan_for_hashes_custom_list.txt"
    $bool_scan_for_hashes_custom = $true
    Write-Warning "Custom Hash Scan Detected!"
}
else
{
    $bool_scan_for_hashes_custom = $false
}

if(Test-Path ".\scan_for_filenames_list.txt" -PathType Leaf)
{
    $txtfile_scan_for_filenames_custom_list = Get-Content -Path ".\scan_for_filenames_list.txt"
    $bool_scan_for_filenames_custom = $true
    Write-Warning "Custom Filename Scan Detected!"
}
else
{
    $bool_scan_for_filenames_custom = $false
}

###array creation
#########################################################################
$array_hashbad_found = New-Object System.Collections.ArrayList
#$ArrayEXACTPathFileFound.GetType()

$array_scan_for_hashes_custom = New-Object System.Collections.ArrayList
#$ArrayEXACTPathFileFound.GetType()

$ArrayEXACTPathFileFound = New-Object System.Collections.ArrayList
#$ArrayEXACTPathFileFound.GetType()

$ArrayJustFileNames = New-Object System.Collections.ArrayList
#$ArrayJustFileNames.Count

$ArrayofHashes = New-Object System.Collections.ArrayList
#$ArrayofHashes.Count

$ArrayVirusTotalMatches = New-Object System.Collections.ArrayList



if ($bool_scan_for_filenames_custom -eq $true)
{
    foreach($filelocation in $txtfile_scan_for_filenames_custom_list)
    {
        $resultfullfilepath = $false
        $resultfullfilepath = Test-Path $filelocation -PathType Leaf
    
        #Write-Host $filelocation
        #Write-Host $resultfullfilepath    
        $justfilename = Split-Path $filelocation -leaf
        $ArrayJustFileNames.Add($justfilename) > $null
        #this stores the filename for non file path speciifc later
    
    
        $outcome = "[" + $resultfullfilepath + "] - " + $filelocation
        if ($resultfullfilepath -eq $True)
        {
            $ArrayEXACTPathFileFound.Add($outcome) > $null
            #Write-Host $outcome
        }
        else {
            #false
            #Write-Host $outcome
        }
    }
}

Write-Host "Custom DIR Select $customscanpath"
Write-Host "Scanning for files changed in last $daysX days passing to array!!"

$ArrayfullfileList = Get-ChildItem -Path $customscanpath -File -Filter * -Recurse -ErrorAction SilentlyContinue -Force -Verbose | Where-Object{
    Write-Progress "Scanning $($_.Fullname) __ Accessed $($_.LastWriteTime)";
    #Sleep -Milliseconds 250
    if ($($_.LastWriteTime) -gt (Get-Date).AddDays(-$daysX))
    {
        #Write-Progress "Filename - $($_.Fullname)"; $true
        $true;
        #Start-Sleep -Milliseconds 250
        #Write-Warning "$($_.Fullname) Modified last 4 days! ADDED TO CHECK LIST!"
        Write-Progress -Activity "$($_.Fullname) Modified last 4 days! ADDED TO CHECK LIST!"

    }
    else
    {
        #older than 4
        #Write-Host "FALSE - File is older than 4 days!"; $false
    }

}   
Write-Progress -Completed -Activity "Clearing Progress Box Message" #hacks found by luck




$saveto = $evidenceoutput + "$filenamedate-customdir-filesfound.csv"
Write-Host "Exporting files as CSV to.... $saveto"
$ArrayfullfileList | Export-Csv -Path $saveto -NoTypeInformation


$recentfilecount = $ArrayfullfileList.Length
Write-Host "Custom Dir - Recent Files ($daysX) found count = " $recentfilecount

$h = 1
if($recentfilecount -gt 0)
{
    Write-Host "##### SHA256 COMPUTATION START" -BackgroundColor DarkGreen
    foreach($hashfilescan in $ArrayfullfileList)
    {
        #sleep -Milliseconds 1000
        $hashfilelocation = $hashfilescan.Fullname
        $fileexiststohash = Test-Path $hashfilelocation -PathType Leaf
        if ($fileexiststohash -eq $True)
        {
            Write-Progress -Activity "Computing SHA256 Hash $hashfilescan" -Status "$h of $recentfilecount"
            #Write-Host "Computing SHA256 Hash $hashfilescan - $h of $recentfilecount"
            $getfilehash = Get-FileHash $hashfilelocation -Algorithm SHA256
            $strhash256 = $getfilehash.Hash
            $ArrayofHashes.Add($strhash256) > $null
            #Write-Host "Adding $strhash256 to hash array"
        }
        $h++
    }
    #sleep -Milliseconds 1000
}
else {
    Write-Host "No Custom Dir Files Found - Recent Files ($daysX) found count = " $recentfilecount
}

$c1 = $txtfile_scan_for_hashes_custom_list.Count
$c2 = $ArrayofHashes.Count
$actions_count = ($c1 * $c2)
Write-Host "Total Actions $actions_count"

Write-Host "Custom DIR Hashes of Files - Saved to Array!"
Write-Host "Saving Hashes to CSV File now...will take a moment...!"
$saveto = ($evidenceoutput + "$filenamedate-customdir-recentfiles-hashed.txt")
Write-Output $ArrayofHashes | Out-File -FilePath $saveto

#$i = 1
#not needed, maybe not yet.
$h = 1
if ($bool_scan_for_hashes_custom -eq $true)
{     
    Write-Host "##### CUSTOMDIR FILE HASH SCAN - START" -BackgroundColor DarkGreen
    foreach($txthash_compare256 in $txtfile_scan_for_hashes_custom_list){
        foreach ($256hashed in $ArrayofHashes)
        {
            Write-Progress -Activity "Comparing $txthash_compare256 against $256hashed" -Status "$h of $actions_count"
            if ($txthash_compare256 -eq $256hashed)
            {
                Write-Warning "Bad Hash Found!!!!!! $txthash_compare256"
                $array_hashbad_found.Add($txthash_compare256) > $null
            }
            #Sleep -Milliseconds 250
            $h++
        }
        #$i++
    }
}


if ($bool_vtotalscan = $true)
{

    $h = 1
    $apicount = 0
    $hashcount = $ArrayofHashes.Count
    foreach ($256hashedbravo in $ArrayofHashes)
    {


        #now copare against virus total
 
        Try {

            #$strhash256 = "654D82796414D54C285219A71849CB8A39301363363AB72045C4ADD9585352F2" #not exist
            #$strhash256 = "2f6bba2bf111a1d7462aee41511f6fb2ebaaff4468171c537b6f7c5b7bab702f" #exists
        
                $RestMethod = @{}
                $RestMethod = @{
                    Method  = 'GET'
                    Uri     = "https://www.virustotal.com/api/v3/search?query="+ $256hashedbravo
                    #Uri     = "https://www.virustotal.com/api/v3/files"+ $strhash256
                    #Uri     = "http://www.virustotal.com/api/v3/domains/$DomainName"
                    #Uri     = "http://www.virustotal.com/api/v3/ip_addresses/$IPAddress"
                    #Uri     = "https://www.virustotal.com/api/v3/urls/$Url"
                    #Uri     = "https://www.virustotal.com/api/v3/files/$Hash"
                    #Uri     = "https://www.virustotal.com/api/v3/analyses/$SearchQueryEscaped"
        
                    Headers = @{
                        "Accept"   = "application/json"
                        'X-Apikey' = $vtotal_apikey
                    }
                }    
                
        
                if ($apicount -le $apimaxcalls)
                {
                    Write-Progress -Activity "Checking against VirusTotal - SHA256 Hash $256hashedbravo" -Status "$h of $hashcount"
                    $InvokeApiOutput = Invoke-RestMethod @RestMethod -ErrorAction Stop
                    #Write-Host $InvokeApiOutput.GetType()
                    #KEEP $InvokeApiOutput.data.attributes | Get-Member #remember this one!
        
                    $check1_sha256 = $InvokeApiOutput.data.attributes.sha256
                    if($check1_sha256.Length -eq 0)
                    {
                        Write-Host "API($apicount) | SHA2 value from VTOTAL = BLANK | Searched for $256hashedbravo"
                    }
                    else
                    {
                        Write-Host "API($apicount) | SHA2 value from VTOTAL ="+ $check1_sha256 -BackgroundColor DarkRed
                    }
        
                    #Write-Host "SHA2 value from FILE ="+ $256hashedbravo
        
                    if($check1_sha256 -eq $256hashedbravo)
                    {
                        $vtotal_outcome = "WARNING! MATCHED FILENAME = "+ $256hashedbravo.Fullname
                        Write-Warning $vtotal_outcome -BackgroundColor DarkRed
                        $ArrayVirusTotalMatches.Add($vtotal_outcome)
                    }
                    else {
                        <# Action when all if and elseif conditions are false #>
                        #Write-host "GOOD! File Not Found! No Data Response Returned"
                    }
                    $apicount++
        
                }
                else
                {
                    Write-Warning "Too many API calls, more than 50+!"
                    break;
                }
                Write-Host "API CALLS USED - $apicount of (script limit $apimaxcalls)"
        
            } catch {
                if ($PSBoundParameters.ErrorAction -eq 'Stop')
                {
                    throw
                } else {
                    Write-Warning -Message "API Call to virus total failed"
                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
                }
            }

        
    }

}

Write-Host "##### EXPORTING RESULTS TO TXT/CSV!" -BackgroundColor DarkGreen

if($ArrayVirusTotalMatches.Count > 0)
{
    $saveto = ($evidenceoutput + "$filenamedate-VTOTAL-SHA256-SCAN__WARNING__MATCHESFOUND.txt")
    $ArrayVirusTotalMatches | Out-File -FilePath "$evidenceoutput$filenamedate-VTOTAL-SHA256-SCAN___WARNING___MATCHESFOUND.txt"
}
else
{
    $saveto = ($evidenceoutput + "$filenamedate-VTOTAL-SHA256-SCAN___CLEAN.txt")
    "No Matches Found on Virus Total, Good news!" | Out-File -FilePath $saveto
}


#TESTS RESULTS
#did we find the files at predicated paths

if(($ArrayEXACTPathFileFound | Measure-Object -Maximum).Maximum -gt 0){
    Write-Host "OBJECTS FOUND - Contact itsupport@!" + $filenamedate
    $saveto = ($evidenceoutput + "$filenamedate-FOUND-exact-file-path-scan.csv")
    $ArrayEXACTPathFileFound | Export-Csv -Path $saveto -NoTypeInformation
} else {
    Write-Host "CLEAN - Nothing Found!" + $filenamedate
    $saveto = ($evidenceoutput + "$filenamedate-CLEAN-exact-file-path-scan.txt")
    Write-Output "CLEAN - Nothing Found!" | Out-File -FilePath $saveto
}


Write-Host "##### STARTING WINDOWS DEFENDER SCAN" -BackgroundColor DarkGreen

#####work in progress windows defender scans


$obj_defender = Get-MpComputerStatus
Write-Host "Defender [Enabled] " + $obj_defender.AntiVirusEnabled
Write-Host "Defender [Last Full Scan] " + $obj_defender.FullScanEndTime + " (Days old"+ $obj_defender.FullScanAge +")"
Write-Host "Defender [Current Signature Version] " + $obj_defender.AntivirusSignatureVersion + " (Days old "+ $obj_defender.AntivirusSignatureAge +" )"
if ($obj_defender.FullScanAge > 0)
{
    Write-Host "Updating Signatures"
    #update defender signature
    Update-MpSignature -verbose
    Write-Host "Defender [Current Signature Version] " + $obj_defender.AntivirusSignatureVersion + " (Days old "+ $obj_defender.AntivirusSignatureAge +" )"   
}

#quick scan
#Start-MpScan -ScanType QuickScan
#full scan
#Start-MpScan -ScanType FullScan

#Add-MpPreference -ExclusionPath "C:\Temp"
#Add-MpPreference -EnableFileHashComputation
#Add-MpPreference -ExclusionExtension "jpg"

#Start-MpScan -ScanType CustomScan -ScanPath $customscanpath
