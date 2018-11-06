# PowerShell script for auto check key and auto continue hardnested attack
# sample
# .\hardnested.ps1 <key>[,otherKey...] -com <com>
# .\hardnested.ps1 FFFFFFFFFFFF -com com3
# .\hardnested.ps1 FFFFFFFFFFFF,0123456789AB -com com3
param (
    [Parameter(Position = 0)]
    [string[]]$keys,
    [string]$com = "com3"
)

function proxmark3 {
    param([Parameter(ValueFromPipeline)]$input) 
    $input | .\proxmark3.exe $com -f | select -Skip 15
}

$sb = [System.Text.StringBuilder]::new()

# get uid
[void]$sb.AppendLine("hf search")
[void]$sb.AppendLine("exit")

$sb.ToString() | proxmark3 | foreach {
    if ($_ -like "* UID : *") {
        $uid = $_.Substring(7, 11).Replace(" ", "")
    }
    if ($_ -like "*Prng detection: HARDENED (hardnested)*") {
        $isHard = $true
    }
}
"UID : " + $uid
"is HARDENED : " + $isHard

if (!(Test-Path $uid".dic")) {
    foreach ($key in $keys)  
    {
        $key+";" | Add-Content $uid".dic"
    }
}

$keyFound = @{}
function Check-Key() {
    [void]$sb.Clear()
    [void]$sb.AppendLine("hf mf chk *1 ? "+$uid+".dic")
    [void]$sb.AppendLine("exit")
    $sb.ToString() | proxmark3 | Select-String -Pattern '\|([0-9]{3})\|  ([0-9a-fA-F]{12})  \| ([0-1]) \|  ([0-9a-fA-F]{12})  \| ([0-1]) \|' | foreach {
        $keyFound[$_.Matches[0].Groups[1].Value + "A"] = @{
            Key = $_.Matches[0].Groups[2].Value;
            Found = $_.Matches[0].Groups[3].Value -like "1";
        }
        $keyFound[$_.Matches[0].Groups[1].Value + "B"] = @{
            Key = $_.Matches[0].Groups[4].Value;
            Found = $_.Matches[0].Groups[5].Value -like "1";
        }
    }
}

Check-Key

$key = ""
$block = 0
$type = "A"
foreach ($i in $keyFound.Keys)  
{
    if ($keyFound[$i].Found) {
        $key = $keyFound[$i].Key
        $block = [int]$i.Remove(3) * 4
        $type = $i.Substring(3)
        break
    }
}

if ([string]::IsNullOrEmpty($key)) {
    "No Key for Hardnested"
    rm $uid".dic"
    return
}

for ($i = 0; $i -le 15; $i++) {
    for ($j = 0; $j -le 1; $j++) {
        if ($j -eq 0) {
            $kt = "A"
        } else {
            $kt = "B"
        }
        if (!$keyFound[$i.ToString().PadLeft(3, '0') + $kt].Found) {
            [void]$sb.Clear()
            $cmd = [string]::Format("hf mf hardnested {0} {1} {2} {3} {4}", $block, $type, $key, $i*4, $kt)
            [void]$sb.AppendLine($cmd)
            [void]$sb.AppendLine("exit")
            $result = ""
            $sb.ToString() | proxmark3 | foreach{
                if ($_ -like "*found*") {
                    $result = $_.ToString().Substring(61, 12)
                }
                $_
            }
            if (![string]::IsNullOrEmpty($result)) {
                "Key found : " + $result
                $result+";" | Add-Content $uid".dic"
                Check-Key
            }
        }
    }
}

[void]$sb.Clear()
[void]$sb.AppendLine("hf mf chk *1 ? d "+$uid+".dic")
[void]$sb.AppendLine("hf mf dump")
[void]$sb.AppendLine("exit")
$sb.ToString() | proxmark3
