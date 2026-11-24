param(
    [switch]$TestMode,
    [int]$LookbackHours = 24,
    [int]$Threshold = 5,
    [int]$WindowMinutes = 5
)

$ErrorActionPreference = 'Stop'

if ($LookbackHours -lt 1 -or $Threshold -lt 1 -or $WindowMinutes -lt 1) {
    throw 'All numeric parameters must be positive.'
}

$ReportFolder = Join-Path ([Environment]::GetFolderPath('Desktop')) 'SOC-Detection-Reports'
New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null

function Test-FailedLogons {
    param(
        [array]$Events,
        [int]$Threshold,
        [int]$WindowMinutes,
        [string]$DataSource
    )

    $Alerts = @(
        foreach ($Group in ($Events | Group-Object Account)) {
            $Sorted = @($Group.Group | Sort-Object TimeCreated)

            for ($i = 0; $i -lt $Sorted.Count; $i++) {
                $WindowStart = $Sorted[$i].TimeCreated.AddMinutes(-$WindowMinutes)
                $Matches = @($Sorted | Where-Object {
                    $_.TimeCreated -ge $WindowStart -and
                    $_.TimeCreated -le $Sorted[$i].TimeCreated
                })

                if ($Matches.Count -ge $Threshold) {
                    [PSCustomObject]@{
                        DetectionTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        FirstFailure = ($Matches | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        LastFailure = $Sorted[$i].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        Account = $Group.Name
                        FailedAttempts = $Matches.Count
                        SourceIPs = (($Matches | ForEach-Object SourceIP | Where-Object { $_ -and $_ -ne '-' } | Sort-Object -Unique) -join '; ')
                        Severity = 'Medium'
                        DetectionRule = "Five Failed Logons in Five Minutes"
                        DataSource = $DataSource
                    }
                    break
                }
            }
        }
    )

    return $Alerts
}

if ($TestMode) {
    $DataSource = 'SIMULATION'
    Write-Host 'MODE: SIMULATION' -ForegroundColor Cyan

    $BaseTime = Get-Date
    $Events = @(1..7 | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $BaseTime.AddSeconds(-($_ * 30))
            EventID = 4625
            Account = 'SOC-LAB-USER'
            SourceIP = '192.0.2.10'
        }
    })
}
else {
    $DataSource = 'LIVE'
    Write-Host 'MODE: LIVE - Reading Windows Security log.' -ForegroundColor Cyan

    try {
        $RawEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4625
            StartTime = (Get-Date).AddHours(-$LookbackHours)
        } -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $RawEvents = @()
        }
        else {
            throw "Security log collection failed: $($_.Exception.Message)"
        }
    }

    $Events = @(
        foreach ($Event in $RawEvents) {
            [xml]$Xml = $Event.ToXml()
            $Fields = @{}

            foreach ($Field in $Xml.Event.EventData.Data) {
                $Fields[$Field.Name] = $Field.'#text'
            }

            [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                EventID = 4625
                Account = "$($Fields.TargetDomainName)\$($Fields.TargetUserName)"
                SourceIP = $Fields.IpAddress
            }
        }
    )
}

Write-Host "Events collected: $($Events.Count)"

if ($Events.Count -eq 0) {
    Write-Host 'NO DATA: No matching authentication failures found.' -ForegroundColor Yellow
    return
}

$Alerts = @(Test-FailedLogons -Events $Events -Threshold $Threshold -WindowMinutes $WindowMinutes -DataSource $DataSource)

if ($Alerts.Count -eq 0) {
    Write-Host 'NO ALERT: No account reached the failure threshold.' -ForegroundColor Green
    return
}

$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$ReportPath = Join-Path $ReportFolder "SOC-Alerts-$DataSource-$TimeStamp.csv"

$Alerts | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

foreach ($Alert in $Alerts) {
    Write-Host "ALERT: $($Alert.Account) - $($Alert.FailedAttempts) failures within $WindowMinutes minutes." -ForegroundColor Red
}

Write-Host "CSV report saved: $ReportPath" -ForegroundColor Cyan