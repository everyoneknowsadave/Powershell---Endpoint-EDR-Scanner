#Written by DPEH
#Powershell Malware Scanner
#Version 0.4

clear
$customscanpath = "C:\Users\"
$customscanpath = "C:\Windows\temp\"
$customscanpath = "C:\Users\DavidHazelden\"
$customscanpath = "C:\Users\Public\"
$customscanpath = "C:\Users\Windows\"

$customscanpath = "C:\Users\DavidHazelden\Desktop"
$daysX = 4
$apimaxcalls = 5
if(Test-Path ".\vtotalapi.txt" -PathType Leaf)
{
    $vtotal_apikey = Get-Content -Path ".\vtotalapi.txt"
}
else
{
    $vtotal_apikey = "4e3cfb44278a31332fac0f7e9889c4d5f41e8643139fdaaf73850279a24e515c"
}

$FileList = Get-Content -Path ".\findfiles.txt"
$ArrayFullPathFileFound = New-Object System.Collections.ArrayList
#$ArrayFullPathFileFound.GetType()
$filenamedate = $(((get-date).ToUniversalTime()).ToString("yyyyMMddTHHmmssZ"))

$ArrayJustFileNames = New-Object System.Collections.ArrayList
#$ArrayJustFileNames.Count

$ArrayofHashes = New-Object System.Collections.ArrayList
#$ArrayofHashes.Count

$ArrayVirusTotalMatches = New-Object System.Collections.ArrayList

foreach($filelocation in $FileList) {
    $resultfullfilepath = $false
    $resultfullfilepath = Test-Path $filelocation -PathType Leaf

    #Write-Host $filelocation
    #Write-Host $resultfullfilepath    
    $justfilename = Split-Path $filelocation -leaf
    $ArrayJustFileNames.Add($justfilename) > $null


    $outcome = "[" + $resultfullfilepath + "]" + $filelocation
    if ($resultfullfilepath -eq $True)
    {
        $ArrayFullPathFileFound.Add($outcome) > $null
        Write-Host $outcome
    }
    else {
        #false
        #Write-Host $outcome
    }
}

#live code
#$ArrayfullfileList = Get-ChildItem -Path $customscanpath -File -Filter * -Recurse -ErrorAction SilentlyContinue -Force -Verbose | Where-Object { Write-Progress "Filename - $($_.Fullname)"; $true }
#$ArrayfullfileList | Export-Csv -Path "C:\temp\$filenamedate-FILEINVENTORY-USERS.csv" -NoTypeInformation

#4 days of changes
#Get-ChildItem -Path . -Recurse| ? {$_.LastWriteTime -gt (Get-Date).AddDays(-4)}
Write-Host "Scanning files changed in last 4 days passing to array!!"
$ArrayfullfileList = Get-ChildItem -Path $customscanpath -File -Filter * -Recurse -ErrorAction SilentlyContinue -Force -Verbose | Where-Object {
    Write-Progress "Scanning $($_.Fullname) __ Accessed $($_.LastWriteTime)";
    if ($($_.LastWriteTime) -gt (Get-Date).AddDays(-$daysX))
    {
        #Write-Progress "Filename - $($_.Fullname)"; $true
        $true;
        Start-Sleep -s 1
        Write-Warning "$($_.Fullname) Modified last 4 days! ADDED TO CHECK LIST!"
    }
    else
    {
        #older than 4
        #Write-Host "FALSE - File is older than 4 days!"; $false
    }
    
}
Write-Progress -Completed -Activity "Clearing Progress Box Message" #hacks found by luck

#debug
#Write-Host "Scanning directory for list of files and passing to array!!"
#$ArrayfullfileList = Get-ChildItem -Path $customscanpath -File -Filter * -Recurse -ErrorAction SilentlyContinue -Force -Verbose | Where-Object { Write-Progress "Filename - $($_.Fullname)"; $true }

Write-Host "Saving directory files to temp as evidence!"
#debug test
$ArrayfullfileList | Export-Csv -Path "C:\temp\4days-20221125T150513Z-FILEINVENTORY-USERS.csv" -NoTypeInformation

$apicount = 0

foreach($hashfilescan in $ArrayfullfileList) {
    #debug#$getfilehash = Get-FileHash C:\temp\20221125T150513Z-FILEINVENTORY-USERS.csv -Algorithm SHA256
    $hashfilelocation = $hashfilescan.Fullname
    $fileexiststohash = Test-Path $hashfilelocation -PathType Leaf
    if ($fileexiststohash -eq $True)
    {
        $getfilehash = Get-FileHash $hashfilelocation -Algorithm SHA256
        $strhash256 = $getfilehash.Hash
        $ArrayofHashes.Add($strhash256) > $null
    }
    #virus total hacks
    #$uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$fileHash"
    #https://www.virustotal.com/ui/files/654D82796414D54C285219A71849CB8A39301363363AB72045C4ADD9585352F2"
    
    #$strhash256 = "654D82796414D54C285219A71849CB8A39301363363AB72045C4ADD9585352F2" #not exist
    #$strhash256 = "2f6bba2bf111a1d7462aee41511f6fb2ebaaff4468171c537b6f7c5b7bab702f" #exists

    $RestMethod = @{}
    $RestMethod = @{
        Method  = 'GET'
        Uri     = "https://www.virustotal.com/api/v3/search?query="+ $strhash256
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

    Try {

        if ($apicount -le $apimaxcalls)
        {

            #$InvokeApiOutput = Invoke-RestMethod @RestMethod -OutFile "C:\temp\test1.txt" -ErrorAction Stop
            $InvokeApiOutput = Invoke-RestMethod @RestMethod -ErrorAction Stop
            #Write-Host $InvokeApiOutput.GetType()
            #KEEP $InvokeApiOutput.data.attributes | Get-Member #remember this one!

            $check1_sha256 = $InvokeApiOutput.data.attributes.sha256

            Write-Host "SHA2 value from VTOTAL ="+ $check1_sha256
            Write-Host "SHA2 value from FILE ="+ $strhash256

            if($check1_sha256 -eq $strhash256)
            {
                $vtotal_outcome = "WARNING! We have a Sha 256 match! FILENAME = "+ $hashfilelocation
                Write-Warning $vtotal_outcome
                $ArrayVirusTotalMatches.Add($vtotal_outcome)
            }
            else {
                <# Action when all if and elseif conditions are false #>
                Write-host "GOOD! File Not Found! No Data Response Returned"
            }
            $apicount++
            Write-Host $apicount

        }
        else {
            
            Write-Warning "Too many API calls, more than 50+!"
        }

    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            throw
        } else {
            Write-Warning -Message "API Call to virus total failed"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        }
    }

}
Write-Host "Hashes Saved to Array!"

Write-Host "Saving Hashes to File now...will take a moment...!"
Write-Output $ArrayofHashes | Out-File -FilePath "C:\temp\$filenamedate-USERS-FILESHASHED.txt"

Write-Host "Saving Virus Total Matches to File"
if($ArrayVirusTotalMatches.Count > 0)
{
    $ArrayVirusTotalMatches | Out-File -FilePath "C:\temp\$filenamedate-VTOTAL-SHA256-SCAN___WARNING___MATCHESFOUND.txt"
}
else {
    "No Matches Found on Virus Total, Good news!" | Out-File -FilePath "C:\temp\$filenamedate-VTOTAL-SHA256-SCAN___CLEAN.txt"
}


#TESTS RESULTS
#did we find the files at predicated paths

if(($ArrayFullPathFileFound | Measure-Object -Maximum).Maximum -gt 0){
    Write-Host "OBJECTS FOUND - Contact itsupport@!" + $filenamedate
    $ArrayFullPathFileFound | Export-Csv -Path "C:\temp\$filenamedate-FOUND-exact-file-path-scan.csv" -NoTypeInformation
} else {
    Write-Host "CLEAN - Nothing Found!" + $filenamedate
    Write-Output "CLEAN - Nothing Found!" | Out-File -FilePath "C:\temp\$filenamedate-CLEAN-scan-custom.txt"
}

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

#can also scan with defender to finish, this works when you have another AV product as well.
#Start-MpScan -ScanType CustomScan -ScanPath $customscanpath
