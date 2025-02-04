function Show-ComputerInfo {
    $usuario = $env:USERNAME

    $nomeComputador = $env:COMPUTERNAME

    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress

    $portasTCP = (Get-NetTCPConnection -State Listen).Count
    $portasUDP = (Get-NetUDPEndpoint).Count

    $portasPerigosas = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080)
    $portasAbertasPerigosas = Get-NetTCPConnection -State Listen | Where-Object { $portasPerigosas -contains $_.LocalPort } | Select-Object LocalPort

    $sistemaOperacional = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption

    $usuarios = Get-LocalUser | Measure-Object | Select-Object -ExpandProperty Count

    $memoriaRAM = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory
    $memoriaRAMGB = [math]::Round($memoriaRAM / 1GB, 2)

    $disco = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object Size, FreeSpace
    $espacoTotalGB = [math]::Round($disco.Size / 1GB, 2)
    $espacoLivreGB = [math]::Round($disco.FreeSpace / 1GB, 2)

    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name

    $ultimaInicializacao = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

    $firewallStatus = (Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }).Count -gt 0

    $updateStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").AUOptions

    $antivirusStatus = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).productState -ne $null

    $bitlockerStatus = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus -eq "On"

    $uacStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA -eq 1

    Write-Host "`n=== Informacoes do Computador ===" -ForegroundColor Cyan
    Write-Host "`n      [Usuario]" -ForegroundColor Yellow
    Write-Host "Usuario atual: $usuario"

    Write-Host "`n       [Rede]" -ForegroundColor Yellow
    Write-Host "Nome do computador: $nomeComputador"
    Write-Host "Endereço IP: $ip"
    Write-Host "Portas TCP abertas: $portasTCP"
    Write-Host "Portas UDP abertas: $portasUDP"
    if ($portasAbertasPerigosas) {
        Write-Host "Portas potencialmente perigosas abertas: " -ForegroundColor Red -NoNewline
        Write-Host ($portasAbertasPerigosas.LocalPort -join ", ") -ForegroundColor Red
    } else {
        Write-Host "Portas potencialmente perigosas abertas: Nenhuma" -ForegroundColor Green
    }

    Write-Host "`n       [Sistema]" -ForegroundColor Yellow
    Write-Host "Sistema Operacional: $sistemaOperacional"
    Write-Host "Quantidade de usuarios no sistema: $usuarios"
    Write-Host "Ultima inicializacao do sistema: $ultimaInicializacao"

    Write-Host "`n      [Hardware]" -ForegroundColor Yellow
    Write-Host "Processador (CPU): $cpu"
    Write-Host "Memória RAM total: $memoriaRAMGB GB"
    Write-Host "Espaco em disco (C:):"
    Write-Host "  - Total: $espacoTotalGB GB"
    Write-Host "  - Livre: $espacoLivreGB GB"

    Write-Host "`n      [Segurança]" -ForegroundColor Yellow
    Write-Host "Firewall ativo: $(if ($firewallStatus) { 'Sim' } else { 'Não' })"
    Write-Host "Atualizacoes automaticas: $(if ($updateStatus -eq 4) { 'Sim' } else { 'Não' })"
    Write-Host "Antivirus instalado e ativo: $(if ($antivirusStatus) { 'Sim' } else { 'Não' })"
    Write-Host "BitLocker ativado: $(if ($bitlockerStatus) { 'Sim' } else { 'Não' })"
    Write-Host "UAC (Controle de Conta de Usuario) ativado: $(if ($uacStatus) { 'Sim' } else { 'Não' })"
    Write-Host "`n===============================`n" -ForegroundColor Cyan

    $detalhes = Read-Host "`n`nVoce deseja obter informacoes mais detalhadas? (1/0)"

    if ($detalhes -eq "1") {
        Get-ComputerInfo | Format-List * 
    }

    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
    $null = Read-Host

    Clear-Host
}

function Show-UserInfo {
    function Show-Menu {
        Clear-Host
        Write-Host "`n`n`n`n`n`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                     === Menu de Informacoes de Usuarios ===                  ║" -ForegroundColor Red
        Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "║  1. Listar Usuarios                                                          ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  2. Visualizar Informacoes de um Usuario                                     ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  3. Exibir Grupos                                                            ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  4. Criar um Usuario                                                         ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  5. Escalar Privilegios                                                      ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  6. Deletar um Usuario        ( CUIDADO !!!)                                 ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  7. Mostrar Usuarios Logados                                                 ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║  8. Voltar ao menu inicial                                                   ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝`n`n" -ForegroundColor Red
    }

    function List-Users {
        Write-Host "`n=== Lista de Usuarios ===" -ForegroundColor Green
        net user | ForEach-Object { Write-Host $_ }
    }

    function Get-UserInfo {
        net user | ForEach-Object { Write-Host $_ }
        $username = Read-Host "`nDigite o nome do usuario"
        Write-Host "`n=== Informacoes do Usuario: $username ===" -ForegroundColor Green
        net user $username | ForEach-Object { Write-Host $_ }
    }

    function Show-Groups {
        Write-Host "`n=== Lista de Grupos ===" -ForegroundColor Green
        net localgroup | ForEach-Object { Write-Host $_ }

        $choice = Read-Host "`nDeseja visualizar os membros de algum grupo? (1 para Sim, 0 para Nao)"
        if ($choice -eq 1) {
            $groupName = Read-Host "Digite o nome do grupo"
            Write-Host "`n=== Membros do Grupo: $groupName ===" -ForegroundColor Green
            net localgroup $groupName | ForEach-Object { Write-Host $_ }
        }
    }

    function Create-User {
        $username = Read-Host "Digite o nome do novo usuario"
        $password = Read-Host "Digite a senha para o novo usuario" -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        net user $username $password /ADD
        Write-Host "Usuario $username criado com sucesso!" -ForegroundColor Green
    }

    function Melhora-Previlegios {  ## FICAR DE OLHO
        while ($true) {
            Clear-Host
            Write-Host "`n`n`n`n`n`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "║                     === Menu de Previlegios Win ===                          ║" -ForegroundColor Red
            Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
            Write-Host "║  1. Adicionar usuario ao grupo de administradores                            ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  2. Adicionar usuario a um grupo especifico                                  ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  3. Adicionar usuario a todos os grupos                                      ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  4. Adicionar user a grupo de Ass.Global        (Ainda nao funciona)         ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  5. Sair                                                                     ║" -ForegroundColor Red
            Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝`n`n" -ForegroundColor Red
            
            
            $opcao = Read-Host "`nEscolha uma opcao (1-5)"

            switch ($opcao) {
                1 {
                    # Opção 1: Adicionar usuário ao grupo de administradores
                    List-Users
                    $username = Read-Host "`n`nDigite o nome do usuario que deseja adicionar ao grupo de administradores"
                    if (-not (UserExists $username)) {
                        Write-Host "Erro: O usuario '$username' nao existe." -ForegroundColor Red
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                        continue
                    }
                    try {
                        net localgroup Administradores $username /ADD
                        Write-Host "Usuario '$username' adicionado ao grupo de administradores com sucesso!" -ForegroundColor Green
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                    catch {
                        Write-Host "Erro ao adicionar o usuario '$username' ao grupo de administradores. Certifique-se de que o PowerShell está sendo executado como administrador." -ForegroundColor Red
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                }
                2 {
                    # Opção 2: Adicionar usuário a um grupo específico
                    List-Users

                    Write-Host "=== Lista de Grupos ===" -ForegroundColor Green
                    net localgroup | ForEach-Object { Write-Host $_ }
                    $username = Read-Host "Digite o nome do usuario que deseja adicionar a um grupo"
                    if (-not (UserExists $username)) {
                        Write-Host "Erro: O usuario '$username' nao existe." -ForegroundColor Red
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                        continue
                    }
                    $groupname = Read-Host "`n`nDigite o nome do grupo ao qual deseja adicionar o usuario"
                    try {
                        net localgroup $groupname $username /ADD
                        Write-Host "Usuario '$username' adicionado ao grupo '$groupname' com sucesso!" -ForegroundColor Green
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                    catch {
                        Write-Host "Erro ao adicionar o usuario '$username' ao grupo '$groupname'. Certifique-se de que o grupo existe e que o PowerShell está sendo executado como administrador." -ForegroundColor Red
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                }
                3 {
                    # Opção 3: Adicionar usuário a todos os grupos
                    List-Users
                    $username = Read-Host "`n`nDigite o nome do usuario que deseja adicionar a todos os grupos"
                    if (-not (UserExists $username)) {
                        Write-Host "Erro: O usuario '$username' nao existe." -ForegroundColor Red
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                        continue
                    }
                    try {
                        $groups = net localgroup | Where-Object { $_ -match "^\*" } | ForEach-Object { $_.TrimStart('*').Trim() }
                        foreach ($group in $groups) {
                            net localgroup $group $username /ADD
                            Write-Host "Usuario '$username' adicionado ao grupo '$group' com sucesso!" -ForegroundColor Green
                        }
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                    catch {
                        Write-Host "Erro ao adicionar o usuario '$username' a todos os grupos. Certifique-se de que o PowerShell está sendo executado como administrador." -ForegroundColor Red
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                }
                4 {  ## FUNÇÃO COM POSSIVEL MELHORIA
                     # Solicita o nome do usuário
                    $nomeUsuario = Read-Host "Digite o nome do usuário que deseja adicionar ao grupo"

                    # Define o nome do grupo
                    $nomeGrupo = "Associações de Grupo Global"

                    # Adiciona o usuário ao grupo
                    try {
                        Add-ADGroupMember -Identity $nomeGrupo -Members $nomeUsuario
                        Write-Host "Usuário '$nomeUsuario' adicionado ao grupo '$nomeGrupo' com sucesso!"
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    } catch {
                        Write-Host "Erro ao adicionar o usuário ao grupo: $_"
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                        $null = Read-Host
                    }
                }
                5 {
                    # Opção 5: Sair do loop
                    Write-Host "`nVoltando para menu de Usuarios..." -ForegroundColor Red
                    return
                }
                default {
                    Write-Host "Opcao invalida. Por favor, escolha uma opcao valida (1-5)." -ForegroundColor Red
                }
            }
        }
    }
    ## subfunção da função : Melhora-Previlegios ;
    function UserExists($username) {
        # Verifica se o usuário existe
        $userExists = net user $username 2>&1 | Select-String "O nome da conta poderia não ser encontrado"
        return -not $userExists
    }

    function Delete-User {
        List-Users
        $username = Read-Host "Digite o nome do usuario que deseja deletar"
    
        $confirm = Read-Host "Voce realmente deseja excluir o usuario '$username'? (s/n)"
    
        if ($confirm -eq 's') {
            net user $username /DELETE
            Write-Host "Usuario $username deletado com sucesso!" -ForegroundColor Green
        } else {
            Write-Host "Operação cancelada." -ForegroundColor Yellow
        }
    }

    function Show-LoggedInUsers {
        Write-Host "`n=== Usuarios Atualmente Logados ===" -ForegroundColor Green
        $usuariosLogados = Get-Process -IncludeUserName | Select-Object UserName -Unique
        if ($usuariosLogados.Count -eq 0) {
            Write-Host "Nenhum usuario logado no momento." -ForegroundColor Red
        }
        else {
            $usuariosLogados | ForEach-Object {
                Write-Host "Usuario logado: $($_.UserName)"
            }
        }
    }

    do {
        Show-Menu
        $choice = Read-Host "Escolha uma opcao (1-8)"

        switch ($choice) {
            1 { List-Users }
            2 { Get-UserInfo }
            3 { Show-Groups }
            4 { Create-User }
            5 { Melhora-Previlegios }
            6 { Delete-User }
            7 { Show-LoggedInUsers }
            8 { Write-Host "Saindo..." -ForegroundColor Yellow; break }
            default { Write-Host "Opcao invalida. Tente novamente." -ForegroundColor Red }
        }

        if ($choice -ne 8) {
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
            $null = Read-Host
        }
    } while ($choice -ne 8)
}

function Show-TCPPorts {
    Write-Host "`n              === Portas TCP Abertas ===" -ForegroundColor Green

    $portasTCP = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, State, OwningProcess

    if ($portasTCP.Count -eq 0) {
        Write-Host "Nenhuma porta TCP aberta encontrada." -ForegroundColor Red
        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
        $null = Read-Host

        Clear-Host
    }
    else {
        $portasTCP | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $appName = if ($process) { $process.ProcessName } else { "N/A" }
            $_ | Add-Member -MemberType NoteProperty -Name "AppName" -Value $appName -Force
            $_.State = "Escutando"
            $_
        } | Format-Table -Property LocalAddress, LocalPort, State, OwningProcess, AppName -AutoSize

        $opcao = Read-Host "`nDeseja encerrar algum processo? (1 - Encerrar, 0 - Voltar ao menu)"
        if ($opcao -eq 1) {
            $processID = Read-Host "Digite o ID do processo que deseja encerrar"
            Stop-Process -Id $processID -Force -ErrorAction SilentlyContinue
            if ($?) {
                Write-Host "Processo $processID encerrado com sucesso." -ForegroundColor Green
            }
            else {
                Write-Host "Falha ao encerrar o processo $processID." -ForegroundColor Red
            }
        }
        elseif ($opcao -eq 0) {
            Write-Host "Voltando ao menu inicial." -ForegroundColor Yellow
        }
        else {
            Write-Host "Opção inválida. Voltando ao menu inicial." -ForegroundColor Red
        }

        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
        $null = Read-Host

        Clear-Host
    }

    Write-Host "=========================`n"
}

function Show-UDPPorts {
    Write-Host "`n              === Portas UDP Abertas ===" -ForegroundColor Yellow

    
    $portasUDP = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess

    if ($portasUDP.Count -eq 0) {
        Write-Host "Nenhuma porta UDP aberta encontrada." -ForegroundColor Red
    }
    else {
        $portasUDP | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $appName = if ($process) { $process.ProcessName } else { "N/A" }
            $_ | Add-Member -MemberType NoteProperty -Name "AppName" -Value $appName -Force
            $_ | Add-Member -MemberType NoteProperty -Name "State" -Value "Escutando" -Force
            $_
        } | Format-Table -Property LocalAddress, LocalPort, State, OwningProcess, AppName -AutoSize

        $opcao = Read-Host "`nDeseja encerrar algum processo? (1 - Encerrar, 0 - Voltar ao menu)"
        if ($opcao -eq 1) {
            $processID = Read-Host "Digite o ID do processo que deseja encerrar"
            Stop-Process -Id $processID -Force -ErrorAction SilentlyContinue
            if ($?) {
                Write-Host "Processo $processID encerrado com sucesso." -ForegroundColor Green
            }
            else {
                Write-Host "Falha ao encerrar o processo $processID." -ForegroundColor Red
            }
        }
        elseif ($opcao -eq 0) {
            Write-Host "Voltando ao menu inicial." -ForegroundColor Yellow
        }
        else {
            Write-Host "Opção inválida. Voltando ao menu inicial." -ForegroundColor Red
        }
    }

    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
    $null = Read-Host

    Clear-Host

    Write-Host "=========================`n"
}

function Show-Apps {
    $usuarioAtivo = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $processos = Get-Process | Where-Object { $_.SessionId -eq (Get-Process -Id $PID).SessionId } | Select-Object Id, ProcessName, MainWindowTitle, Path

    Write-Host "`n=== Aplicativos em Execucao no Perfil do Usuario Ativo ===" -ForegroundColor Cyan
    $processos | Format-Table -AutoSize -Property Id, ProcessName, MainWindowTitle, Path

    $opcao = Read-Host "`nDeseja encerrar algum processo? (1 - Encerrar, 0 - Voltar ao menu)"
    if ($opcao -eq 1) {
        $processID = Read-Host "Digite o ID do processo que deseja encerrar"
        Stop-Process -Id $processID -Force -ErrorAction SilentlyContinue
        if ($?) {
            Write-Host "Processo $processID encerrado com sucesso." -ForegroundColor Green
        }
        else {
            Write-Host "Falha ao encerrar o processo $processID." -ForegroundColor Red
        }
    }
    elseif ($opcao -eq 0) {
        Write-Host "Voltando ao menu inicial." -ForegroundColor Yellow
    }
    else {
        Write-Host "Opcao invalida. Voltando ao menu inicial." -ForegroundColor Red
    }
    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
    $null = Read-Host

    Clear-Host

}

function Wmap {
    function Show-Menu {
        Clear-Host
        Write-Host "`n`n`n`n`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                                 === WMap ===                                 ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 1. Pingar IP                                                 ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 2. Criar Lista de IP                                         ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 3. Descobrir Maquinas Ativas de um IP                        ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 4. Pingar Porta Espcifica ( info )                           ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 5. Pingar todas as Portas de um ip                           ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 6. Pingar 100 portas mais usadas                             ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "║                 0. Menu Principal                                            ║" -ForegroundColor Red
        Write-Host "║                                                                              ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝`n`n" -ForegroundColor Red
    }

    function Pingar-Ip {
        Write-Host "`n"
        $ip = Read-Host "Digite o IP"
        Write-Host "`nEfetuando ping no host: $ip"
        $pingResult = Test-Connection -ComputerName $ip -Count 3 -Quiet
        if ($pingResult) {
            Write-Host "`n               - - RED TEAM - - " -ForegroundColor Red
            ping -n 5 $ip | Select-String "bytes=32"
            Write-Host "`n`nO host: $ip :ONLINE" -ForegroundColor Green
        } else {
            ping -n 5 $ip | Select-String "bytes=32"
            Write-Host "`n`nFalha ao pingar o host: $ip :OFFLINE" -ForegroundColor Red
        }
    }

    function Criar-Lista {
        Write-Host "`n"
        $baseIP = Read-Host "Digite a parte inicial do IP (Ex: 192.168.10.)"
    
        if (-not $baseIP.EndsWith(".")) {
            Write-Host "Formato inválido. Certifique-se de incluir o ponto final (Ex: 192.168.10.)" -ForegroundColor Red
            return
        }

        Write-Host "`nGerando lista de IPs..." -ForegroundColor Yellow

        foreach ($i in 1..254) {
            $ip = "$baseIP$i"
            Write-Host $ip
        }

        Write-Host "`nLista de IPs gerada com sucesso!" -ForegroundColor Green
        }

    function Pingar-Ip-Rede {
        Write-Host "`n"
        $baseIP = Read-Host "Digite a parte inicial do IP (Ex: 192.168.10.) ( esse comando vai pingar todos os endereços de 1 - 254 pode levar até 20 minutos)"

        # Verifica se o usuário digitou um valor válido
        if (-not $baseIP.EndsWith(".")) {
            Write-Host "Formato inválido. Certifique-se de incluir o ponto final (Ex: 192.168.10.)" -ForegroundColor Red
            return
        }

        Write-Host "`nPingando endereços de 1 a 254 do IP $baseIP ..." -ForegroundColor Yellow

        # Loop para pingar cada IP na rede
        foreach ($ip in 1..254) {
            $fullIP = "$baseIP$ip" # Concatena a base do IP com o número atual
            Write-Host "`nPingando $fullIP..." -ForegroundColor Cyan
            $result = ping -n 1 $fullIP | Select-String "bytes=32"

            # Exibe o resultado do ping
            if ($result) {
                Write-Host "$fullIP respondeu ao ping." -ForegroundColor Green
            } else {
                Write-Host "$fullIP não respondeu ao ping." -ForegroundColor Red
            }
        }

        Write-Host "`nPing concluído!" -ForegroundColor Yellow
    }

    function Pingar-Porta-IP {
        Write-Host "`n"
        $ip = Read-Host "Digite o IP (alvo)"
        $porta = Read-Host "Digite a porta"

        if (-not $ip -or -not $porta) {
            Write-Host "Dados Inseridos corretamente..." -ForegroundColor Red
            return
        }

        # Valida se a porta é um número válido
        if (-not ($porta -match '^\d+$') -or [int]$porta -lt 1 -or [int]$porta -gt 65535) {
            Write-Host "`nPorta inválida. A porta deve ser um número entre 1 e 65535." -ForegroundColor Red
            return
        }

        Write-Host "`nVerificando a porta $porta no IP $ip..." -ForegroundColor Yellow

        # Testa a conexão com o IP e a porta e obtém detalhes completos
        $resultado = Test-NetConnection -ComputerName $ip -Port $porta -WarningAction SilentlyContinue

        # Exibe os detalhes da conexão
        Write-Host "`n=== Detalhes da Conexão ===" -ForegroundColor Cyan
        Write-Host "ComputerName: $($resultado.ComputerName)" -ForegroundColor Green
        Write-Host "RemoteAddress: $($resultado.RemoteAddress)" -ForegroundColor Green
        Write-Host "RemotePort: $($resultado.RemotePort)" -ForegroundColor Green
        Write-Host "InterfaceAlias: $($resultado.InterfaceAlias)" -ForegroundColor Green
        Write-Host "SourceAddress: $($resultado.SourceAddress)" -ForegroundColor Green
        Write-Host "PingReplyDetails (RTT): $($resultado.PingReplyDetails.RoundtripTime) ms" -ForegroundColor Green
        Write-Host "TcpTestSucceeded: $($resultado.TcpTestSucceeded)" -ForegroundColor Green

        # Resultado do teste de porta
        if ($resultado.TcpTestSucceeded) {
            Write-Host "`nPorta $porta está aberta no IP $ip." -ForegroundColor Green
        } else {
            Write-Host "`nPorta $porta está fechada no IP $ip." -ForegroundColor Red
        }
    }

    function Validar-IP {
        param (
            [string]$ip
        )
        # Expressão regular para validar um endereço IPv4
        $regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return ($ip -match $regex)
    }

    function Pingar-Todas-Portas-Ip {
        Write-Host "`n"
        Write-Host "Obs:(Esta acao pode levar alguns minutos:65535 portas)"
    
        do {
            $ip = Read-Host "Digite o IP (alvo)"
            if (-not (Validar-IP $ip)) {
                Write-Host "Endereço IP inválido. Tente novamente." -ForegroundColor Red
                return
            }
        } while (-not (Validar-IP $ip))
    
        Write-Host "`nIniciando Scan..."
        $totalPortas = 65535
        $portasAbertas = @()

        for ($porta = 1; $porta -le $totalPortas; $porta++) {
            if (Test-NetConnection $ip -Port $porta -WarningAction SilentlyContinue -InformationLevel Quiet) {
                Write-Host "Porta $porta Aberta" -ForegroundColor Green
                $portasAbertas += $porta
            } else {
                # Write-Host "Porta $porta Fechada" -ForegroundColor Red
                Continue
            }
        }

        Write-Host "Portas abertas: $($portasAbertas -join ', ')"
    }

    function Pingar-Portas-Comuns-Ip {
        Write-Host "`n"
    
        do {
            Write-Host "`n"
            Write-Host "Obs:(Esta acao pode levar alguns minutos:100 portas)"
            $ip = Read-Host "Digite o IP (alvo)"
            if (-not (Validar-IP $ip)) {
                Write-Host "Endereço IP inválido. Tente novamente." -ForegroundColor Red
                return
            }
        } while (-not (Validar-IP $ip))
    
        Write-Host "`nIniciando Scan nas 100 portas mais comuns..."

       $portasComuns = @(
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 
            445, 465, 500, 512, 513, 514, 587, 636, 873, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 
            1433, 1434, 1701, 1723, 1812, 1813, 1900, 2049, 2181, 2375, 2376, 2483, 2484, 3306, 3389, 3478, 
            4500, 5000, 5060, 5061, 5353, 5355, 5432, 5555, 5900, 5985, 5986, 6000, 6379, 6667, 7000, 8080, 
            8081, 8192, 8443, 8888, 9000, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 25565, 27017, 
            27018, 27019, 28015, 28017, 31337, 32768, 37777, 49152, 49153, 49154, 49155, 49156, 49157, 
            49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165
        )

        $portasAbertas = @()

        foreach ($porta in $portasComuns) {
            if (Test-NetConnection $ip -Port $porta -WarningAction SilentlyContinue -InformationLevel Quiet) {
                Write-Host "Porta $porta Aberta" -ForegroundColor Green
                $portasAbertas += $porta
            } else {
                Write-Host "Porta $porta Fechada" -ForegroundColor Red
            }
        }

        Write-Host "Portas abertas: $($portasAbertas -join ', ')"
    }

    do {
        Show-Menu
        $choice = Read-Host "Escolha uma opcao (1-0)"

        switch ($choice) {
            1 { Pingar-Ip }
            2 { Criar-Lista }
            3 { Pingar-Ip-Rede }
            4 { Pingar-Porta-IP }
            5 { Pingar-Todas-Portas-Ip }
            6 { Pingar-Portas-Comuns-Ip }
            0 { Write-Host "Voltando ao menu principal..." -ForegroundColor Yellow; break }
            default { Write-Host "Opcao invalida. Tente novamente." -ForegroundColor Red }
        }

        if ($choice -ne 0) {
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
            $null = Read-Host
        }
    } while ($choice -ne 0)
}

function Busca-Por-DNS {
        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
        }

        # === Funções ===
        function ScanHeaders {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Escaneando Headers..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Method Head -Headers $headers -ErrorAction Stop
                Write-Host "`n📌 O servidor roda:" -ForegroundColor Green
                $response.Headers.Server
            } catch {
                Write-Host "⚠️ Erro ao buscar headers: $_" -ForegroundColor Red
            }
        }

        function ScanOptions {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Verificando métodos HTTP suportados..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Method Options -Headers $headers -ErrorAction Stop
                Write-Host "`n✅ Métodos permitidos pelo servidor:" -ForegroundColor Green
                $response.Headers.Allow
            } catch {
                Write-Host "⚠️ Erro ao buscar métodos OPTIONS: $_" -ForegroundColor Red
            }
        }

        function ScanLinks {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Procurando links na página..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                Write-Host "`n🔗 Links encontrados:" -ForegroundColor Green
                $response.Links.Href | Select-String http
            } catch {
                Write-Host "⚠️ Erro ao buscar links: $_" -ForegroundColor Red
            }
        }

        function ScanHTML {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Obtendo código-fonte do HTML..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                Write-Host "`n📝 Código HTML recebido:" -ForegroundColor Green
                Write-Host $response.Content.Substring(0, 500) # Exibe os primeiros 500 caracteres
            } catch {
                Write-Host "⚠️ Erro ao obter o HTML: $_" -ForegroundColor Red
            }
        }

        function ScanTech {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Detectando tecnologias utilizadas..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                if ($response.Headers["x-powered-by"]) {
                    Write-Host "`n⚙️ Tecnologia detectada:" -ForegroundColor Green
                    $response.Headers["x-powered-by"]
                } else {
                    Write-Host "❌ Nenhuma tecnologia detectada nos headers."
                }
            } catch {
                Write-Host "⚠️ Erro ao buscar tecnologias: $_" -ForegroundColor Red
            }
        }

        function ScanStatusCode {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Obtendo código de status HTTP..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                Write-Host "`n✅ Status Code:" -ForegroundColor Green
                $response.StatusCode
            } catch {
                Write-Host "⚠️ Erro ao obter Status Code: $_" -ForegroundColor Red
            }
        }

        function ScanTitle {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Obtendo título da página..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                if ($response.ParsedHtml.title) {
                    Write-Host "`n🏷️ Título da página:" -ForegroundColor Green
                    $response.ParsedHtml.title
                } else {
                    Write-Host "❌ Nenhum título encontrado."
                }
            } catch {
                Write-Host "⚠️ Erro ao obter título da página: $_" -ForegroundColor Red
            }
        }

        function ScanRobotsTxt {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Procurando robots.txt..." -ForegroundColor Cyan
                $robotsUrl = "$url/robots.txt"
                $response = Invoke-WebRequest -Uri $robotsUrl -Headers $headers -ErrorAction Stop
                Write-Host "`n🤖 Conteúdo do robots.txt:" -ForegroundColor Green
                Write-Host $response.Content
            } catch {
                Write-Host "⚠️ Erro ao buscar robots.txt: $_" -ForegroundColor Red
            }
        }

        function ScanSitemap {
            param ([string]$url)
            try {
                Write-Host "`n🔍 Verificando sitemap.xml..." -ForegroundColor Cyan
                $sitemapUrl = "$url/sitemap.xml"
                $response = Invoke-WebRequest -Uri $sitemapUrl -Headers $headers -ErrorAction Stop
                Write-Host "`n🗺️ Sitemap encontrado:" -ForegroundColor Green
                Write-Host $response.Content.Substring(0, 500)
            } catch {
                Write-Host "⚠️ Erro ao buscar sitemap.xml: $_" -ForegroundColor Red
            }
        }

        function ScanPorts {
            param ([string]$host)
            $ports = @(21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080)
            Write-Host "`n🔍 Escaneando portas comuns..." -ForegroundColor Cyan
            foreach ($port in $ports) {
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $tcp.Connect($host, $port)
                    Write-Host "🟢 Porta $port aberta!" -ForegroundColor Green
                    $tcp.Close()
                } catch {
                    Write-Host "🔴 Porta $port fechada."
                }
            }
        }

        function RunAllScans {
            param ([string]$url)

            Write-Host "`n=== Iniciando todas as verificações para a URL: $url ===`n" -ForegroundColor Cyan

            # 1. Captura Headers do Servidor
            Write-Host "`n=== 1. Captura Headers do Servidor ===" -ForegroundColor Yellow
            ScanHeaders -url $url

            # 2. Descobre os Métodos HTTP Permitidos
            Write-Host "`n=== 2. Descobre os Métodos HTTP Permitidos ===" -ForegroundColor Yellow
            ScanOptions -url $url

            # 3. Lista os Links Encontrados no HTML
            Write-Host "`n=== 3. Lista os Links Encontrados no HTML ===" -ForegroundColor Yellow
            ScanLinks -url $url

            # 4. Obtém Código-Fonte do HTML
            Write-Host "`n=== 4. Obtém Código-Fonte do HTML ===" -ForegroundColor Yellow
            ScanHTML -url $url

            # 5. Detecta Tecnologias Utilizadas
            Write-Host "`n=== 5. Detecta Tecnologias Utilizadas ===" -ForegroundColor Yellow
            ScanTech -url $url

            # 6. Obtém Código de Status HTTP
            Write-Host "`n=== 6. Obtém Código de Status HTTP ===" -ForegroundColor Yellow
            ScanStatusCode -url $url

            # 7. Obtém o <title> da Página
            Write-Host "`n=== 7. Obtém o <title> da Página ===" -ForegroundColor Yellow
            ScanTitle -url $url

            # 8. Verifica o arquivo robots.txt
            Write-Host "`n=== 8. Verifica o arquivo robots.txt ===" -ForegroundColor Yellow
            ScanRobotsTxt -url $url

            # 9. Verifica se o site possui um Sitemap
            Write-Host "`n=== 9. Verifica se o site possui um Sitemap ===" -ForegroundColor Yellow
            ScanSitemap -url $url

            Write-Host "`n=== Todas as verificações foram concluídas! ===`n" -ForegroundColor Cyan
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
            $null = Read-Host
        }

        # === Menu Principal ===
        while ($true) {
            Clear-Host
            Write-Host "`n`n`n`n`n`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║                     === Menu de busca por DNS ===                            ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  1. Captura Headers do Servidor                                              ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  2. Descobre os Métodos HTTP Permitidos                                      ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  3. Lista os Links Encontrados no HTML                                       ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  4. Obtém Código-Fonte do HTML                                               ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  5. Detecta Tecnologias Utilizadas                                           ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  6. Obtém Código de Status HTTP                                              ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  7. Obtém o <title> da Página                                                ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  8. Verifica o arquivo robots.txt                                            ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║  9. Verifica se o site possui um Sitemap                                     ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║ 10. Faz um Scan Rápido das Portas Comuns                                     ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║ 11. Rodar todas opcoes ( 1 a 9 )                                             ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "║ 12. Voltar para o Menu-Principal                                             ║" -ForegroundColor Red
            Write-Host "║                                                                              ║" -ForegroundColor Red
            Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝`n`n" -ForegroundColor Red

            $opcao = Read-Host "`nEscolha uma opcao (1-11)"
        
            switch ($opcao) {
                1 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanHeaders -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                2 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanOptions -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                3 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanLinks -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                4 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanHTML -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                5 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanTech -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                6 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanStatusCode -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                7 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanTitle -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                8 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanRobotsTxt -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                9 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanSitemap -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                10 {
                    $host = Read-Host "`nDigite o host ou IP (ex: exemplo.com ou 192.168.1.1)"
                    ScanPorts -host $host
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
                11{
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    RunAllScans -url $url
                }
                12 {
                    Write-Host "`nSaindo..." -ForegroundColor Green
                    return
                }
                default {
                    Write-Host "`n❌ Opção inválida. Por favor, escolha uma opção entre 1 e 11." -ForegroundColor Red
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                }
            }
        }
    }

while ($true) {
    Clear-Host
    Write-Host "`n`n`n`n`n`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                          === Menu Principal ===                              ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 1. Mostrar informações do computador                         ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 2. Informações avançadas de Usuários                         ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 3. Listar portas TCP abertas                                 ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 4. Listar portas UDP abertas                                 ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 5. Listar aplicativos em USO                                 ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 6. WMap                                                      ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 7. DNS Request's                                             ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "║                 0. Sair                                                      ║" -ForegroundColor Green
    Write-Host "║                                                                              ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    $opcao = Read-Host "`nEscolha uma opção (1-0)" 

    if ($opcao -eq 1) {
        Show-ComputerInfo
    }
    elseif ($opcao -eq 2) {
        Show-UserInfo
    }
    elseif ($opcao -eq 3) {
        Show-TCPPorts
    }
    elseif ($opcao -eq 4) {
        Show-UDPPorts
    }
    elseif ($opcao -eq 5) {
        Show-Apps
    }
    elseif ($opcao -eq 6){
        Wmap
    }
    elseif ($opcao -eq 7){
        Busca-Por-DNS
    }
    elseif ($opcao -eq 0) {
        Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                                  Saindo...                                   ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        break
    }
    else {
        Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
        Write-Host "`nPressione qualquer tecla para continuar..."
        $null = Read-Host

        Clear-Host
    }
}
