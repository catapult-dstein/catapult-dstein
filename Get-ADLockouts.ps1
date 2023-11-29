#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
	Query AD domain controllers to identify locked user accounts
.DESCRIPTION
	Query AD domain controllers to get a list of all locked user accounts
.PARAMETER OutputFile
	Path to save results. Default is "c:\Tools\lockout.txt"
.PARAMETER SelectServers
	Optional. Prompts to select domain controllers to query
	Default (when not referenced) is to query all domain controllers
.EXAMPLE
	.\Get-ADLockouts.ps1
.EXAMPLE
	.\Get-ADLockouts.ps1 -SelectServers
.NOTES
	1.1.0 - 2023-02-02 - Quisitive, David Stein
		Added -SelectServers option to limit the domain controllers to be queried

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
	INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
	FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
	DEALINGS IN THE SOFTWARE.
#>
[CmdletBinding()]
param (
	[parameter()][string]$OutputFile = "C:\Tools\lockout.txt",
	[parameter()][switch]$SelectServers
)

$dcs = (Get-ADDomainController -Filter * | Sort-Object Name | Select-Object -ExpandProperty Name)
if ($SelectServers) {
	$dcs = @($dcs | Out-GridView -Title "Select Domain Controllers to query" -OutputMode Multiple)
}
[int]$total = $dcs.Count
[int]$counter = 1

[int]$EventID = 4740
[string]$LogName = "Security"
[datetime]$StartTime = (Get-Date).AddDays(-3)

$results = @()

foreach ($dc in $dcs) {
	Write-Host "$counter of $total - $dc"
	try {
		$events = Get-WinEvent -ComputerName $dc -FilterHashtable @{Logname = $LogName; ID = $EventID; StartTime = $StartTime} -ErrorAction Stop
		Foreach ($event in $events) {
			$res = [pscustomobject]@{
				Computername   = $dc
				Time           = $event.TimeCreated
				Username       = $event.Properties.value[0]
				CallerComputer = $event.Properties.value[1]
			}
			$results += $res
			$res | FT -Wrap
		}
	}
	catch {
		$msg = $_.Exception.Message
		if ($msg -like '*No events were found*') {
			Write-Host "No matching events found"
		} else {
			Write-Warning "ERROR: $dc - $msg"
		}
	}
	$counter++
}

if ($results.Count -gt 0) {
	$results | Out-File -FilePath $outputfile -Force
	Write-Host "results saved to $outputfile"
}
