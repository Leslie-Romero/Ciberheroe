$pathJSON = "C:\scripts\eventos.json"

$minutosAtras = 10

$eventIds = @(4800, 4802, 1074, 4625, 4624)

$startTime = (Get-Date).AddMinutes(-$minutosAtras)

try {

    $eventosRaw = Get-WinEvent -FilterHashTable @{

        LogName   = 'ForwardedEvents'

        ID        = $eventIds

        StartTime = $startTime

    } -ErrorAction SilentlyContinue

    $resultados = foreach ($e in $eventosRaw) {

        $xml = [xml]$e.ToXml()

        $eventData = $xml.Event.EventData.Data

        # Inicializamos variables por cada evento

        $usuario = ""

        $accionDetalle = "N/A"

        $isHello = $false

        # LÓGICA PARA EVENTO 1074 (System - Apagar/Reiniciar)

        if ($e.Id -eq 1074) {

            # En el 1074: Data[6] es el usuario y Data[4] es el tipo de acción

            $usuario = ($eventData | Select-Object -Index 6).'#text'

            $accionDetalle = ($eventData | Select-Object -Index 4).'#text' # "Apagar" o "Reiniciar"
        }

        # LÓGICA PARA EVENTOS DE SEGURIDAD (4624, 4625, 4800, 4802)

        else {

            $usuario = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'

            $logonType = ($eventData | Where-Object { $_.Name -eq "LogonType" }).'#text'

            $authPackage = ($eventData | Where-Object { $_.Name -eq "AuthenticationPackageName" }).'#text'

            $isHello = ($authPackage -eq "CloudAP") -or ($logonType -eq "7")

            $accionDetalle = switch ($e.Id) {

                4624 { "Login Exitoso" }

                4625 { "Login Fallido" }

                4800 { "Bloqueo Manual" }

                4802 { "Bloqueo Inactividad" }

                Default { "Seguridad" }

            }

        }

        # Limpiar el nombre de usuario (quitar el dominio si existe para la web)

        if ($usuario -like "*\\*") { $usuario = $usuario.Split("\\")[1] }

        [PSCustomObject]@{

            Fecha        = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

            ID           = $e.Id

            Equipo       = $e.MachineName.Split(".")[0] # Nombre corto del equipo

            Usuario      = $usuario

            Accion       = $accionDetalle

            WindowsHello = $isHello

            Mensaje      = $e.Message.Split(".")[0].Replace("`n", "").Replace("`r", "")

        }

    }

    if ($resultados) {

        $resultados | ConvertTo-Json -Compress | Out-File $pathJSON -Encoding UTF8

    }

}

catch {

    Write-Warning "Error al exportar eventos: $_"

}