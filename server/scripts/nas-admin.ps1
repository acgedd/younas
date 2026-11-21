# The owner's console for friend accounts and shares, through the server's admin API on this
# machine. No elevation needed. The owner's password is asked each run (hidden) and never stored;
# the session is logged out at the end.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\YourNAS\server\scripts\nas-admin.ps1 <command> [arguments]
#
#   users                          list accounts
#   add-user <name>                create an account; prints its one-time temporary password
#   reset-password <name>          new temporary password; ends the account's sessions
#   disable <name> | enable <name> disabling also ends its sessions
#   logout-user <name>             ends every session of the account
#   shares                         list shares and who may use them
#   add-share <name>               a shared folder (you get write access to it)
#   grant <share> <user> read|write
#   revoke <share> <user>
#   delete-share <share>           removes the share only; its files stay on disk
#
# -Owner <name> skips the username question. -BaseUrl must be a loopback address: the password
# goes over plain HTTP, so it never leaves this machine.
param(
    [Parameter(Position = 0)][string]$Command,
    [Parameter(Position = 1)][string]$Arg1,
    [Parameter(Position = 2)][string]$Arg2,
    [Parameter(Position = 3)][string]$Arg3,
    [string]$Owner,
    [string]$BaseUrl
)

. (Join-Path $PSScriptRoot 'host-common.ps1')

$commands = 'users', 'add-user', 'reset-password', 'disable', 'enable', 'logout-user',
    'shares', 'add-share', 'grant', 'revoke', 'delete-share'
if ($Command -notin $commands) {
    [Console]::Error.WriteLine("usage: nas-admin.ps1 <$($commands -join '|')> [arguments]")
    exit 2
}

if (-not $BaseUrl) {
    $port = 8000
    if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) { $port = (Read-YourNASConfig $ConfigPath).Port }
    $BaseUrl = "http://127.0.0.1:$port"
}
$BaseUrl = $BaseUrl.TrimEnd('/')
$parsed = $null
if (-not [Uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$parsed) -or
    $parsed.Scheme -notin 'http', 'https' -or
    $parsed.Host -notin '127.0.0.1', 'localhost', '[::1]') {
    [Console]::Error.WriteLine('nas-admin: -BaseUrl must be a loopback address (127.0.0.1)')
    exit 2
}

function Fail([string]$message) {
    [Console]::Error.WriteLine("nas-admin: $message")
    exit 1
}

function Read-Line([string]$prompt, [switch]$Secret) {
    if ([Console]::IsInputRedirected) {
        Write-Host -NoNewline "${prompt}: "
        return [Console]::In.ReadLine()
    }
    if (-not $Secret) { return Read-Host $prompt }
    $secure = Read-Host $prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

$script:Headers = @{}

function Invoke-Api([string]$method, [string]$path, $body = $null) {
    $request = @{
        Method = $method; Uri = "$BaseUrl$path"; Headers = $script:Headers
        UseBasicParsing = $true; ContentType = 'application/json; charset=utf-8'
    }
    if ($null -ne $body) { $request.Body = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Compress)) }
    try {
        # Through a variable: Windows PowerShell 5.1 emits a JSON array as one object, and
        # returning the variable enumerates it.
        $result = Invoke-RestMethod @request
        return $result
    } catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        $code = ''; $text = $_.Exception.Message
        try {
            $parsed = $_.ErrorDetails.Message | ConvertFrom-Json
            $code = $parsed.error.code; $text = $parsed.error.message
        } catch { }
        if ($status) { throw "HTTP $status $code - $text" }
        throw "cannot reach the server at ${BaseUrl}: $text"
    }
}

function Find-User([string]$name) {
    $wanted = "$name".Trim().ToLowerInvariant()
    $user = @(Invoke-Api GET '/api/v1/admin/users') | Where-Object { $_.username -eq $wanted }
    if (-not $user) { throw "no account named '$name'" }
    return $user
}

function Find-Share([string]$name) {
    $share = @(Invoke-Api GET '/api/v1/admin/shares') | Where-Object { $_.name -ieq "$name".Trim() }
    if (-not $share) { throw "no share named '$name'" }
    return $share
}

function Show-Password([string]$user, [string]$password) {
    Write-Host ''
    Write-Host "  Temporary password for ${user}: $password" -ForegroundColor Yellow
    Write-Host '  Shown once, never stored. Send it privately; it must be changed at the first'
    Write-Host '  login and stops working after 7 days.'
}

function Need([string]$value, [string]$what) {
    if (-not $value) { throw "missing $what (see the usage at the top of this script)" }
}

$ownerName = $Owner
if (-not $ownerName) { $ownerName = Read-Line 'Owner username' }
$password = Read-Line 'Owner password' -Secret
try {
    $login = Invoke-Api POST '/api/v1/auth/login' @{ username = $ownerName; password = $password }
} catch {
    Fail "login failed: $($_.Exception.Message)"
} finally {
    $password = $null
}
if ($login.user.role -ne 'owner') { Fail 'that account is not the owner' }
$script:Headers = @{ Authorization = "Bearer $($login.token)" }

try {
    switch ($Command) {
        'users' {
            Invoke-Api GET '/api/v1/admin/users' | ForEach-Object {
                [pscustomobject]@{
                    username = $_.username; role = $_.role; disabled = $_.disabled
                    must_change_password = $_.must_change_password
                    created = ([DateTimeOffset]::Parse("$($_.created_at)", [Globalization.CultureInfo]::InvariantCulture)).ToLocalTime().ToString('yyyy-MM-dd HH:mm')
                }
            } | Format-Table -AutoSize | Out-String | Write-Host
        }
        'add-user' {
            Need $Arg1 'the new username'
            $created = Invoke-Api POST '/api/v1/admin/users' @{ username = $Arg1 }
            Write-Host "Created account $($created.username)."
            Show-Password $created.username $created.temporary_password
        }
        'reset-password' {
            Need $Arg1 'the username'
            $user = Find-User $Arg1
            $reset = Invoke-Api POST "/api/v1/admin/users/$($user.id)/password-reset"
            Write-Host "Password of $($user.username) reset; its sessions ended."
            Show-Password $user.username $reset.temporary_password
        }
        { $_ -in 'disable', 'enable' } {
            Need $Arg1 'the username'
            $user = Find-User $Arg1
            $null = Invoke-Api PATCH "/api/v1/admin/users/$($user.id)" @{ disabled = ($Command -eq 'disable') }
            Write-Host "$($user.username): ${Command}d."
        }
        'logout-user' {
            Need $Arg1 'the username'
            $user = Find-User $Arg1
            $null = Invoke-Api DELETE "/api/v1/admin/users/$($user.id)/sessions"
            Write-Host "$($user.username): every session ended."
        }
        'shares' {
            $names = @{}
            Invoke-Api GET '/api/v1/admin/users' | ForEach-Object { $names[$_.id] = $_.username }
            Invoke-Api GET '/api/v1/admin/shares' | ForEach-Object {
                $grants = @($_.grants | ForEach-Object { "$($names[$_.user_id])=$($_.level)" }) -join ', '
                [pscustomobject]@{ share = $_.name; grants = $grants }
            } | Format-Table -AutoSize -Wrap | Out-String | Write-Host
        }
        'add-share' {
            Need $Arg1 'the share name'
            $share = Invoke-Api POST '/api/v1/admin/shares' @{ name = $Arg1 }
            Write-Host "Created share $($share.name) (you have write access)."
        }
        'grant' {
            Need $Arg1 'the share name'; Need $Arg2 'the username'
            if ($Arg3 -notin 'read', 'write') { throw "the level must be read or write" }
            $share = Find-Share $Arg1; $user = Find-User $Arg2
            $null = Invoke-Api PUT "/api/v1/admin/shares/$($share.id)/grants/$($user.id)" @{ level = $Arg3 }
            Write-Host "$($user.username) may now $Arg3 in $($share.name)."
        }
        'revoke' {
            Need $Arg1 'the share name'; Need $Arg2 'the username'
            $share = Find-Share $Arg1; $user = Find-User $Arg2
            $null = Invoke-Api DELETE "/api/v1/admin/shares/$($share.id)/grants/$($user.id)"
            Write-Host "$($user.username) no longer has access to $($share.name)."
        }
        'delete-share' {
            Need $Arg1 'the share name'
            $share = Find-Share $Arg1
            $null = Invoke-Api DELETE "/api/v1/admin/shares/$($share.id)"
            Write-Host "Share $($share.name) removed. Its files were not deleted."
        }
    }
    $exitCode = 0
} catch {
    [Console]::Error.WriteLine("nas-admin: $($_.Exception.Message)")
    $exitCode = 1
} finally {
    try { $null = Invoke-Api POST '/api/v1/auth/logout' } catch { }
}
exit $exitCode
