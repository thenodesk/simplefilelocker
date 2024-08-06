# Use python method for modulus to handle negative values
function Python-Modulus { param ([int]$dividend, [int]$divisor)
    return [int]($dividend - [math]::Floor($dividend / $divisor) * $divisor)
}

# Function to calculate path depth
function Get-Depth { param ($path)
    return ($path -split '\\').Count
}

# Handle invalid windows characters
function Handle-Win-Chars { param ([char]$c, [bool]$mapin)
    $map_in  = ' .\/:*?"<>|'
    $map_out = 'µ¶¢£¤¥¦§¨©ª'
    if ($mapin)
    {
        $idx = $map_in.IndexOf($c)
        if ($idx -ne -1) { $c = $map_out[$idx] }
    }
    else
    {
        $idx = $map_out.IndexOf($c)
        if ($idx -ne -1) { $c = $map_in[$idx] }
    }
    return $c
}

function Encrypt-Name { param ([string]$s)
    $offset = $s.Length
    $clist = @()
    for ($i = 0; $i -lt $offset; $i++)
    {
        $c = [byte]$s[$i]
        $c -= 32
        $c += $offset
        $c += $i
        $c = Python-Modulus -dividend $c -divisor 95
        $c += 32
        $c = [char]$c
        $c = Handle-Win-Chars -c $c -mapin $true
        $clist += $c
    }
    return $clist -join ''
}

function Decrypt-Name { param ([string]$s)
    $offset = $s.Length
    $clist = @()
    for ($i = 0; $i -lt $offset; $i++)
    {
        $c = $s[$i]
        $c = Handle-Win-Chars -c $c -mapin $false
        $c = [byte]$c
        $c -= 32
        $c -= $offset
        $c -= $i
        $c = Python-Modulus -dividend $c -divisor 95
        $c += 32
        $c = [char]$c
        $clist += $c
    }
    return $clist -join ''
}

function Encrypt-File { param ([string]$file, [int]$numOfBytes=32, [int]$offset=22)
    # Open the file stream for reading and writing
    $fs = [System.IO.File]::Open($file, 'Open', 'ReadWrite')

    try {
        # Create a BinaryReader and BinaryWriter
        $reader = New-Object System.IO.BinaryReader($fs)
        $writer = New-Object System.IO.BinaryWriter($fs)

        # Get the file size
        $fsize = $fs.Length

        # Calculate the number of bytes to read
        $qtdBytes = [Math]::Min($numOfBytes, $fsize)

        # Read the bytes
        $newBytes = $reader.ReadBytes($qtdBytes)

        # Move to the start of the file to overwrite with encrypted bytes
        $fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

        # Encrypt the bytes
        for ($i = 0; $i -lt $qtdBytes; $i++) {
            $b = $newBytes[$i]
            $b = Python-Modulus -dividend $($b + $offset) -divisor 256
            $newBytes[$i] = [byte]$b
        }
        
        # Write the new bytes
        $writer.Write($newBytes)
    }
    finally {
        # Clean up resources
        $reader.Close()
        $writer.Close()
        $fs.Close()
    }
}

function Decrypt-File { param ([string]$file, [int]$numOfBytes=32, [int]$offset=22)
    $fs = [System.IO.File]::Open($file, 'Open', 'ReadWrite')

    try {
        $reader = New-Object System.IO.BinaryReader($fs)
        $writer = New-Object System.IO.BinaryWriter($fs)

        $fsize = $fs.Length
        $qtdBytes = [Math]::Min($numOfBytes, $fsize)

        $newBytes = $reader.ReadBytes($qtdBytes)
        $fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

        for ($i = 0; $i -lt $qtdBytes; $i++) {
            $b = $newBytes[$i]
            $b = Python-Modulus -dividend $($b - $offset) -divisor 256
            $newBytes[$i] = [byte]$b
        }
        $writer.Write($newBytes)
    } catch { Write-Host "ERRO: $b" }
    finally {
        # Clean up resources
        $reader.Close()
        $writer.Close()
        $fs.Close()
    }
}

function Gen-Keys { param ([string]$password, [int]$nameLength)
    $k1 = 0
    $k2 = 0
    for ($i = 0; $i -lt $password.Length; $i++)
    {
        $curOp = ([int]$password[$i] + $nameLength) * ($i+1)
        $k1 += $curOp
        $k2 -= $curOp
    }
    $k1 = [char]((Python-Modulus -dividend $k1 -divisor 95) + 32)
    $k2 = [char]((Python-Modulus -dividend $k2 -divisor 95) + 32)
    $k1 = Handle-Win-Chars -c $k1 -mapin $True
    $k2 = Handle-Win-Chars -c $k2 -mapin $True
    
    return @($k1, $k2) -join ''
}

function Encrypt { param ([string]$InitFolder, [string]$pass)
    $items = Get-ChildItem -Path "./$InitFolder" -Recurse
    $items = $items | Sort-Object { Get-Depth $_.FullName } -Descending

    $items | ForEach-Object {
        $fname = $_.FullName
        $relpath = Resolve-Path -LiteralPath $fname -Relative
        Write-Host "Encrypting: `"$relpath`""

        $keys = Gen-Keys -password $pass -nameLength $_.Name.Length
        $finalName = (Encrypt-Name -s $_.Name) + $keys

        if ($finalName.Length -le 247)
        {
            try {
            if (-not $_.PSIsContainer) { Encrypt-File -file $_.FullName }
            Rename-Item -LiteralPath $fname -NewName $finalName -ErrorAction Stop
            }
            catch {
                Write-Error "$_"
            }
            Write-Host 'Success' -ForegroundColor Green
        }
        else
        {
            Write-Host 'Failed (folder or file name too big)' -ForegroundColor Red
        }
    }

    Write-Host "`nItems encrypted.`n"
}

function Decrypt { param ([string]$InitFolder, [string]$pass)
    $items = Get-ChildItem -Path "./$InitFolder" -Recurse
    $items = $items | Sort-Object { Get-Depth $_.FullName } -Descending

    $items | ForEach-Object {
        $fname = $_.FullName
        $relpath = Resolve-Path -LiteralPath $fname -Relative
        Write-Host "Decrypting: `"$relpath`""

        if ($_.Name.Length -lt 3)
        {
            Write-Host "Failed (name too short)" -ForegroundColor Red
            return
        }

        $keys = Gen-Keys -password $pass -nameLength $($_.Name.Length - 2)
        $actualKey = $_.Name.Substring($_.Name.Length - 2)

        if ($actualKey -eq $keys)
        {
            try {
                if (-not $_.PSIsContainer) { Decrypt-File -file $_.FullName }
                Rename-Item -LiteralPath $fname -NewName (Decrypt-Name -s $_.Name.Substring(0, $_.Name.Length - 2)) -ErrorAction Stop
            }
            catch {
                Write-Error "$_"
            }
            Write-Host 'Success' -ForegroundColor Green
        }
        else
        {
            Write-Host 'Failed (Invalid password)' -ForegroundColor Red
        }
    }

    Write-Host "`nItems decrypted.`n"
}

function Check-Folder { param ([string]$path)
    if (-not (Test-Path -Path $path -PathType Container))
    {
        Write-Host "The folder '$path' was not found."
        return $False
    }
    return $True
}


$jsonPath = ".\lck_config.json"
$jsonModified = $False

if (Test-Path -Path $jsonPath -PathType Leaf)
{
    $jsonConfig = Get-Content -Path $jsonPath | ConvertFrom-Json
}
else
{
    $jsonConfig = [pscustomobject]@{ folder=""}
    $jsonModified = $True
}

if (-not $jsonConfig.folder)
{
    $jsonConfig.folder = Read-Host "Enter a base folder to encrypt data"
    while (-not (Check-Folder -path $jsonConfig.folder))
    {
        $jsonConfig.folder = Read-Host "Enter a base folder to encrypt data"
    }
    $jsonModified = $True
}

if ($jsonModified) { $jsonConfig | ConvertTo-Json | Set-Content -Path $jsonPath }


# Mode: 1 = Encrypt, 2 = Decrypt

#$workingDir = Get-Location

$retry = $True
while ($retry)
{
    $opt = Read-Host "1 - Encrypt`n2 - Decrypt`n3 - Change base folder ($($jsonConfig.folder))`n4 - Exit`n`nEnter an option"

    switch ($opt)
    {
        1 { 
            $pass = Read-Host "Type password to encrypt `"$($jsonConfig.folder)`" data"
            $pass = Encrypt-Name -s $pass
            Encrypt -InitFolder $jsonConfig.folder -pass $pass
        }

        2 { 
            $pass = Read-Host "Type password to decrypt `"$($jsonConfig.folder)`" data"
            $pass = Encrypt-Name -s $pass
            Decrypt -InitFolder $jsonConfig.folder -pass $pass
        }

        3 {
            #Write-Host "Current base folder: `"$($jsonConfig.folder)`"" -ForegroundColor Yellow
            $jsonConfig.folder = Read-Host "Enter a new base folder"
            while (-not (Check-Folder -path $jsonConfig.folder))
            {
                $jsonConfig.folder = Read-Host "Enter a new base folder"
            }
            $jsonConfig | ConvertTo-Json -Compress | Set-Content -Path $jsonPath
        }

        4 { $retry = $False }
        default { Write-Host "`nInvalid option." }
    }
}



