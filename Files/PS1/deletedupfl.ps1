''
$filepath = Read-Host 'Entrer le chemin du repertoire à analyser (e.g. C:\Temp, C:\)'
 
If (Test-Path $filepath) {
''
Write-Warning 'Recherche de doublon ... Merci de patienter ...'
 
$duplicates = Get-ChildItem $filepath -File -Recurse `
-ErrorAction SilentlyContinue |
Get-FileHash |
Group-Object -Property Hash |
Where-Object Count -GT 1
 
If ($duplicates.count -lt 1)
 
{
Write-Warning 'Aucun doublon détecté!'
Break ''
}
 
else {
Write-Warning "Doublons trouvés!"
$result = foreach ($d in $duplicates)
{
$d.Group | Select-Object -Property Path, Hash
}
 
$date = Get-Date -Format "MM/dd/yyy"
$itemstomove = $result |
Out-GridView -Title `
"Selectionne le fichier (CTRL pour plusieurs) puis appuie sur OK. Les fichiers selectionné seront déplacé sur C:\ILMN" `
-PassThru
 
If ($itemstomove)
 
{
New-Item -ItemType Directory `
-Path $env:SystemDrive\ILMN -Force
Move-Item $itemstomove.Path `
-Destination $env:SystemDrive\ILMN -Force
''
Write-Warning `
"Tache termine. Les fichiers ont été déplacé au chemin suivant: C:\ILMN"
 
Start-Process "C:\ILMN"
}
 
else
{
Write-Warning "Operation annulé. Aucun fichier sélectionné."
}
}
}
else
{
Write-Warning `
"Aucun dossier trouvé. Essayez avec le chemin complet. ex C:\photos\patrick"
}