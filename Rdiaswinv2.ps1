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
    Write-Host "Endereco IP: $ip "
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
    Write-Host "Memoria RAM total: $memoriaRAMGB GB"
    Write-Host "Espaco em disco (C:):"
    Write-Host "  - Total: $espacoTotalGB GB"
    Write-Host "  - Livre: $espacoLivreGB GB"

    Write-Host "`n      [Seguranca]" -ForegroundColor Yellow
    Write-Host "Firewall ativo: $(if ($firewallStatus) { 'Sim' } else { 'Nao' })"
    Write-Host "Atualizacoes automaticas: $(if ($updateStatus -eq 4) { 'Sim' } else { 'Nao' })"
    Write-Host "Antivirus instalado e ativo: $(if ($antivirusStatus) { 'Sim' } else { 'Nao' })"
    Write-Host "BitLocker ativado: $(if ($bitlockerStatus) { 'Sim' } else { 'Nao' })"
    Write-Host "UAC (Controle de Conta de Usuario) ativado: $(if ($uacStatus) { 'Sim' } else { 'Nao' })"

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
        Write-Host "`n`n`n`n`n`n=====================================================" -ForegroundColor Cyan
        Write-Host "       === Menu de Informacoes de Usuarios ===                 " -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  1. Listar Usuarios                             ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  2. Visualizar Informacoes de um Usuario        ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  3. Exibir Grupos                               ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  4. Criar um Usuario                            ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  5. Escalar Privilegios                         ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  6. Deletar um Usuario   ( CUIDADO !!!)         ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  7. Mostrar Usuarios Logados                    ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "||  8. Voltar ao menu inicial                      ||" -ForegroundColor Cyan
        Write-Host "||                                                 ||" -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
    }

    function List-Users1 {
        Write-Host "`n=== Lista de Usuarios ===" -ForegroundColor Cyan
        net user | ForEach-Object { Write-Host $_ }
        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
        $null = Read-Host
    }

    function List-Users {
        Write-Host "`n=== Lista de Usuarios ===" -ForegroundColor Cyan
        net user | ForEach-Object { Write-Host $_ }
    }

    function Get-UserInfo {
        net user | ForEach-Object { Write-Host $_ }
        $username = Read-Host "`nDigite o nome do usuario"
        Write-Host "`n=== Informacoes do Usuario: $username ===" -ForegroundColor Cyan
        net user $username | ForEach-Object { Write-Host $_ }
        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
        $null = Read-Host
    }

    function Show-Groups {
        Write-Host "`n=== Lista de Grupos ===" -ForegroundColor Cyan
        net localgroup | ForEach-Object { Write-Host $_ }

        $choice = Read-Host "`nDeseja visualizar os membros de algum grupo? (1 para Sim, 0 para Nao)"
        if ($choice -eq 1) {
            $groupName = Read-Host "Digite o nome do grupo"
            Write-Host "`n=== Membros do Grupo: $groupName ===" -ForegroundColor Cyan
            net localgroup $groupName | ForEach-Object { Write-Host $_ }
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
            $null = Read-Host
        }
    }

  function Create-User {
    $username = Read-Host "`nDigite o nome do novo usuario"
    $password = Read-Host "Digite a senha para o novo usuario" -AsSecureString
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    )

    Try {
        # Tenta criar o usuário
        net user $username $plainPassword /ADD | Out-Null

        # Aguarda alguns segundos para garantir que o sistema atualize
        Start-Sleep -Seconds 1

        # Verifica se o usuário realmente foi criado
        if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
            Write-Host "`nUsuario '$username' criado com sucesso!" -ForegroundColor Green
        }
        else {
            Write-Host "`nErro: Usuario '$username' nao foi criado." -ForegroundColor Red
        }
    }
    Catch {
        Write-Host "`nFalha ao tentar criar o usuario: $_" -ForegroundColor Red
    }

    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
    $null = Read-Host
}
function Melhora-Previlegios {
    while ($true) {
        Clear-Host
        Write-Host "`n`n`n`n`n`n"
        Write-Host "||========================================================================||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||===                    Menu de Previlegios Win                       ===||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||========================================================================||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||  [1] Adicionar usuario ao grupo de administradores                     ||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||  [2] Adicionar usuario a um grupo especifico                           ||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||  [3] Adicionar usuario a todos os grupos                               ||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||  [4] Adicionar usuario ao grupo de Ass.Global (Ainda nao funciona)     ||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||  [5] Sair                                                              ||" -ForegroundColor DarkCyan
        Write-Host "||                                                                        ||" -ForegroundColor DarkCyan
        Write-Host "||========================================================================||`n`n" -ForegroundColor DarkCyan

        $opcao = Read-Host "`nEscolha uma opcao (1-5)"

        switch ($opcao) {
            1 {
                List-Users
                $username = Read-Host "`n`nDigite o nome do usuario que deseja adicionar ao grupo de administradores"
                if (-not (UserExists $username)) {
                    Write-Host "Erro: O usuario '$username' nao existe." -ForegroundColor Red
                    continue
                }
                try {
                    net localgroup Administradores $username /ADD | Out-Null
                    $grupo = net localgroup Administradores
                    if ($grupo -match $username) {
                        Write-Host "Usuario '$username' adicionado ao grupo de administradores com sucesso!" -ForegroundColor Green
                    } else {
                        Write-Host "Erro: Usuario '$username' nao foi adicionado ao grupo de administradores." -ForegroundColor Red
                    }
                }
                catch {
                    Write-Host "Erro ao adicionar o usuario '$username'. Execute o PowerShell como administrador." -ForegroundColor Red
                }
                Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
                $null = Read-Host
            }

            2 {
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

                $groupname = Read-Host "`nDigite o nome do grupo ao qual deseja adicionar o usuario"
                try {
                    net localgroup $groupname $username /ADD | Out-Null
                    $verifica = net localgroup $groupname
                    if ($verifica -match $username) {
                        Write-Host "Usuario '$username' adicionado ao grupo '$groupname' com sucesso!" -ForegroundColor Green
                    } else {
                        Write-Host "Erro: Usuario '$username' nao foi adicionado ao grupo '$groupname'." -ForegroundColor Red
                    }
                }
                catch {
                    Write-Host "Erro: Certifique-se de que o grupo '$groupname' existe e o PowerShell está em modo administrador." -ForegroundColor Red
                }
                Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                $null = Read-Host
            }

            3 {
                List-Users
                $username = Read-Host "`nDigite o nome do usuario que deseja adicionar a todos os grupos"
                if (-not (UserExists $username)) {
                    Write-Host "Erro: O usuario '$username' nao existe." -ForegroundColor Red
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                    $null = Read-Host
                    continue
                }
                try {
                    $groups = net localgroup | Where-Object { $_ -match "^\*" } | ForEach-Object { $_.TrimStart('*').Trim() }
                    foreach ($group in $groups) {
                        net localgroup $group $username /ADD | Out-Null
                        $verifica = net localgroup $group
                        if ($verifica -match $username) {
                            Write-Host "Usuario '$username' adicionado ao grupo '$group' com sucesso!" -ForegroundColor Green
                        } else {
                            Write-Host "Erro: Usuario '$username' nao foi adicionado ao grupo '$group'." -ForegroundColor Red
                        }
                    }
                }
                catch {
                    Write-Host "Erro ao adicionar o usuario a todos os grupos. Use PowerShell como administrador." -ForegroundColor Red
                }
                Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                $null = Read-Host
            }

            4 {
                $nomeUsuario = Read-Host "Digite o nome do usuario que deseja adicionar ao grupo"
                $nomeGrupo = "Associações de Grupo Global"  # Nome sem acento, como padrão

                try {
                    Add-ADGroupMember -Identity $nomeGrupo -Members $nomeUsuario
                    Write-Host "Usuario '$nomeUsuario' adicionado ao grupo '$nomeGrupo' com sucesso!" -ForegroundColor Green
                }
                catch {
                    Write-Host "Erro ao adicionar o usuario ao grupo: $_" -ForegroundColor Red
                }
                Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                $null = Read-Host
            }

            5 {
                Write-Host "`nVoltando para menu de Usuarios..." -ForegroundColor Red
                return
            }

            default {
                Write-Host "`nOpção inválida. Por favor, escolha uma opção entre 1 e 5." -ForegroundColor Red
                Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
                $null = Read-Host
            }
        }
    }
}

    function UserExists($username) {
        $userExists = net user $username 2>&1 | Select-String "O nome da conta poderia nao ser encontrado"
        return -not $userExists
    }

    function Delete-User {
        List-Users
        $username = Read-Host "Digite o nome do usuario que deseja deletar"
        $confirm = Read-Host "Voce realmente deseja excluir o usuario '$username'? (s/n)"
        
        if ($confirm.ToLower() -eq 's') {
            if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
                try {
                    net user $username /DELETE
                    Write-Host "Usuario $username deletado com sucesso!" -ForegroundColor Cyan
                } catch {
                    Write-Host "Erro ao deletar o usuario: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "Usuario '$username' nao encontrado." -ForegroundColor Red
            }
        } else {
            Write-Host "Operacao cancelada." -ForegroundColor Yellow
        }
        
        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
        $null = Read-Host
    }

    function Show-LoggedInUsers {
        Write-Host "`n=== Usuarios Atualmente Logados ===" -ForegroundColor Cyan
        $usuariosLogados = Get-Process -IncludeUserName | Select-Object UserName -Unique
        if ($usuariosLogados.Count -eq 0) {
            Write-Host "Nenhum usuario logado no momento." -ForegroundColor Red
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
            $null = Read-Host
        }
        else {
            $usuariosLogados | ForEach-Object {
                Write-Host "`nUsuario logado: $($_.UserName)"
            }
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Cyan
            $null = Read-Host
        }
    }

    while ($true) {
        Show-Menu
        $opcao = Read-Host "`nEscolha uma opcao (1-8)"

        switch ($opcao) {
            1 { List-Users1 }
            2 { Get-UserInfo }
            3 { Show-Groups }
            4 { Create-User }
            5 { Melhora-Previlegios }
            6 { Delete-User }
            7 { Show-LoggedInUsers }
            8 { return }
            default { Write-Host "`nOpcao invalida. Escolha um numero de 1 a 8." -ForegroundColor Red 
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Red
                    $null = Read-Host
            }
        }
    }
}

function Servicos {

    function Mostrar_menu{
        Clear-Host
        Write-Host "`n`n`n`n`n"
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "||              === SERVICOS ===                ||" -ForegroundColor Yellow
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   1. Servicos atuais                         ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   2. Listar portas UDP abertas               ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   3. Listar portas TCP abertas               ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   0. Menu Principal                          ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "==================================================`n`n" -ForegroundColor Yellow

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
                Write-Host "Voltando ao menu de servicos." -ForegroundColor Yellow
            }
            else {
                Write-Host "Opcao invalida. Voltando ao menu de servicos." -ForegroundColor Red
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
                Write-Host "Voltando ao menu de servicos." -ForegroundColor Yellow
            }
            else {
                Write-Host "Opcao invalida. Voltando ao menu de servicos." -ForegroundColor Red
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
            Write-Host "Voltando ao menu de servicos." -ForegroundColor Yellow
        }
        else {
            Write-Host "Opcao invalida. Voltando ao menu de servicos." -ForegroundColor Red
        }
        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Green
        $null = Read-Host

        Clear-Host

    }

    do {
        Mostrar_menu
        $escolha = Read-Host "Escolha uma das opcoes (0-3)"

        switch ($escolha) {
            '1' { Show-Apps }
            '2' { Show-UDPPorts }
            '3' { Show-TCPPorts }
            '0' { Write-Host "`nVoltando para o menu inicial ..." -ForegroundColor Yellow }
            Default { Write-Host "`nOpcao invalida. Escolha um numero entre 0 e 3." -ForegroundColor Red 
                        Write-Host "`nPressione Enter para continuar..." -ForegroundColor Red
                        $null = Read-Host
            }
        }

    } while ($escolha -ne '0')
}

function Wmap {
    function Show-Menu {
        Clear-Host
        Write-Host "`n`n`n`n`n"
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "||                  === WMap ===                ||" -ForegroundColor Yellow
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   1. Descobrir se o Host esta ativo          ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   2. Criar Lista (192.168.10.xxx) 1 a 254    ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   3. Varredura de pings (192.168.10.xxx)     ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   4. Descobrir portas abertas de um ip       ||" -ForegroundColor Yellow 
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   5. Pingar 100 portas mais usadas           ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   6. Pingar Porta Especifica ( info )        ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "||   0. Menu Principal                          ||" -ForegroundColor Yellow
        Write-Host "||                                              ||" -ForegroundColor Yellow
        Write-Host "==================================================`n`n" -ForegroundColor Yellow
    }

    function Pingar-Ip {
        Clear-Host
        Write-Host "`n"
        $ip = Read-Host "Digite o IP"
        Write-Host "`nEfetuando ping no host: $ip" 
        $pingResult = Test-Connection -ComputerName $ip -Count 3 -Quiet
        if ($pingResult) {
            Write-Host "`n                  Efetuando Ping ... " -ForegroundColor Green
            ping -n 2 $ip | Select-String "bytes=32"
            Write-Host "`n`nO host: $ip :ONLINE" -ForegroundColor Green
        } else {
            ping -n 5 $ip | Select-String "bytes=32"
            Write-Host "`n`nFalha ao pingar o host: $ip :OFFLINE" -ForegroundColor Yellow
        }
    }

    function Criar-Lista {
        Write-Host "`n"
        $baseIP = Read-Host "Digite a parte inicial do IP (Ex: 192.168.10.)"
    
        if (-not $baseIP.EndsWith(".")) {
            Write-Host "Formato invalido. Certifique-se de incluir o ponto final (Ex: 192.168.10.)" -ForegroundColor Red
            return
        }

        Write-Host "`nGerando lista de IPs..." -ForegroundColor Yellow

        foreach ($i in 1..254) {
            $ip = "$baseIP$i"
            Write-Host $ip
        }

        Write-Host "`n`nLista de IPs gerada com sucesso!" -ForegroundColor Green
    }
  
    function Varredura-IP {
        
        Write-Host "`nSobre - Este comando ira fazer uma varredura do endereco 1 - 254 ( ate 5 min ) `n`n" -ForegroundColor Yellow
        $baseIP = Read-Host "Digite a parte inicial do IP (Ex: 192.168.10.)"

        if (-not $baseIP.EndsWith(".")) {
            Write-Host "Formato inválido. Certifique-se de incluir o ponto final (Ex: 192.168.10.)" -ForegroundColor Red
            return
        }

        Write-Host "`nPingando enderecos de 1 a 254 do IP $baseIP.." -ForegroundColor Yellow
        Write-Host "Pressione Ctrl+C para cancelar a qualquer momento`n" -ForegroundColor Cyan

        $activeHosts = @()
        $total = 254
        $count = 0

        # Configuração para permitir cancelamento com Ctrl+C
        [console]::TreatControlCAsInput = $false

        try {
            foreach ($ip in 1..254) {
                $count++
                $fullIP = "$baseIP$ip"
                $progress = [math]::Round(($count/$total)*100, 2)
                Write-Progress -Activity "Varredura de rede em andamento" -Status "$progress% completo" -PercentComplete $progress -CurrentOperation "Testando $fullIP"

                # Ping otimizado com timeout reduzido
                $ping = New-Object System.Net.NetworkInformation.Ping
                $reply = $ping.Send($fullIP, 200) # Timeout de 200ms
                
                if ($reply.Status -eq 'Success') {
                    Write-Host "$fullIP respondeu ao ping." -ForegroundColor Green
                    $activeHosts += $fullIP
                }
                # Não exibe os que não responderam para não poluir a tela
            }
        }
        catch {
            Write-Host "`nVarredura interrompida pelo usuário." -ForegroundColor Yellow
        }
        finally {
            Write-Progress -Activity "Varredura de rede" -Completed
            [console]::TreatControlCAsInput = $true
        }

        Write-Host "`nResumo:"
        Write-Host "Hosts ativos encontrados: $($activeHosts.Count)" -ForegroundColor Green
        if ($activeHosts.Count -gt 0) {
            Write-Host "Lista de hosts ativos:"
            $activeHosts | ForEach-Object { Write-Host $_ -ForegroundColor Green }
        }

        Write-Host "`nVarredura concluida!" -ForegroundColor Yellow
    }

    # subfuncao de pingar todas as portas ip
    function Validar-IP {
        param (
            [string]$ip
        )
        $regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return ($ip -match $regex)
    }

    function Pingar-Todas-Portas-Ip { # TOP TOP TOP TESTAR COM MAQ VIRTUAL DEPOIS
        Write-Host "`n"
        Write-Host "Obs: Esta acao pode levar alguns minutos (65535 portas)" -ForegroundColor Yellow
        
        do {
            $ip = Read-Host "`nDigite o IP (alvo)"
            if (-not (Validar-IP $ip)) {
                Write-Host "`nEndereco IP invalido. Tente novamente." -ForegroundColor Yellow 
                return
            } else {
                
            }
        } while (-not (Validar-IP $ip))

        Write-Host "`n- Scan Iniciado -" -ForegroundColor Yellow

        $totalPortas = 65535
        $portasAbertas = @()
        $progress = 0

        [console]::TreatControlCAsInput = $false

        try {
            for ($porta = 1; $porta -le $totalPortas; $porta++) {
                $progress++
                Write-Progress -Activity "Varredura de portas em andamento" `
                    -Status "$([math]::Round(($progress/$totalPortas)*100, 2))% completo" `
                    -PercentComplete ($progress / $totalPortas * 100) `
                    -CurrentOperation "Testando porta $porta"

                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $async = $tcpClient.BeginConnect($ip, $porta, $null, $null)
                    $wait = $async.AsyncWaitHandle.WaitOne(200, $false)

                    if ($wait -and $tcpClient.Connected) {
                        $tcpClient.EndConnect($async)
                        Write-Host "Porta $porta Aberta" -ForegroundColor Green
                        $portasAbertas += $porta
                    }

                    $tcpClient.Close()
                    $tcpClient.Dispose()
                } catch {
                    # Silencia erros
                }
            }
        }
        catch {
            Write-Host "`nVarredura interrompida pelo usuário." -ForegroundColor Yellow
        }
        finally {
            Write-Progress -Activity "Varredura de portas" -Completed
            [console]::TreatControlCAsInput = $true
        }

        Write-Host "`nPortas abertas encontradas: $($portasAbertas.Count)" -ForegroundColor Green
        if ($portasAbertas.Count -gt 0) {
            Write-Host "Lista de portas abertas (ordenadas):"
            $portasAbertas = $portasAbertas | Sort-Object
            $portasAbertas | ForEach-Object { Write-Host $_ -ForegroundColor Green }
        }

        Write-Host "`nVarredura de portas concluída!" -ForegroundColor Yellow
    }
    # subfunção de pingar porta especifica
    function Get-Banner {
        param (
            [string]$ip,
            [int]$porta
        )

        $scheme = if ($porta -in 443, 8443) { "https" } else { "http" }
        $url = "${scheme}://${ip}:${porta}"

        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 4
        }
        catch {
            return @{
                URL = $url
                StatusCode = "Erro"
                StatusDesc = "Falha ao conectar"
                Titulo = "-"
                Server = "-"
                ContentType = "-"
                XPoweredBy = "-"
                Cookies = "-"
                Links = @()
                Robots = "-"
                FaviconHash = "-"
            }
        }

        # Titulo da pagina
        $titulo = if ($response.Content -match '<title>(.*?)</title>') {
            $matches[1]
        } else {
            "[sem título]"
        }

        # Hash do favicon
        try {
            $favicon = Invoke-WebRequest -Uri "$url/favicon.ico" -UseBasicParsing -TimeoutSec 3
            $sha1 = [System.BitConverter]::ToString(
                (New-Object -TypeName System.Security.Cryptography.SHA1Managed).ComputeHash($favicon.Content)
            ).Replace("-", "").ToLower()
        } catch {
            $sha1 = "-"
        }

        # robots.txt
        try {
            $robots = Invoke-WebRequest -Uri "$url/robots.txt" -UseBasicParsing -TimeoutSec 2
            $hasRobots = if ($robots.StatusCode -eq 200) { "Sim" } else { "Nao" }
        } catch {
            $hasRobots = "Nao"
        }

        return @{
            URL = $response.BaseResponse.ResponseUri.AbsoluteUri
            StatusCode = $response.StatusCode
            StatusDesc = $response.StatusDescription
            Titulo = $titulo
            Server = $response.Headers["Server"]
            ContentType = $response.Headers["Content-Type"]
            XPoweredBy = $response.Headers["X-Powered-By"]
            Cookies = $response.Headers["Set-Cookie"]
            Links = ($response.Links | Select-Object -First 5 | ForEach-Object { $_.href })
            Robots = $hasRobots
            FaviconHash = $sha1
        }
    }

    function Pingar-Porta-Especifica {
        <#
        .SYNOPSIS
            Verifica o status de uma porta específica e identifica o serviço e versão.
        
        .EXAMPLE
            Pingar-Porta-Especifica
        #>
        Clear-Host
        Write-Host "`n=== Verificador de Porta ===" -ForegroundColor Cyan

        $ip = Read-Host "Digite o IP (alvo)"
        $porta = Read-Host "Digite a porta"

        # Validações
        if (-not $ip -or -not $porta) {
            Write-Host "Por favor, insira IP e porta corretamente." -ForegroundColor Red
            return
        }

        if (-not ($porta -match '^\d+$') -or [int]$porta -lt 1 -or [int]$porta -gt 65535) {
            Write-Host "Porta inválida. Deve ser um número entre 1 e 65535." -ForegroundColor Red
            return
        }

        Write-Host "`nVerificando porta $porta no IP $ip..." -ForegroundColor Yellow
        $resultado = Test-NetConnection -ComputerName $ip -Port $porta -WarningAction SilentlyContinue

        # Identificação básica do serviço
        $servico = switch ($porta) {
            21     { "FTP" }
            22     { "SSH" }
            23     { "Telnet" }
            25     { "SMTP" }
            53     { "DNS" }
            80     { "HTTP" }
            110    { "POP3" }
            143    { "IMAP" }
            443    { "HTTPS" }
            3306   { "MySQL" }
            3389   { "RDP" }
            5432   { "PostgreSQL" }
            6379   { "Redis" }
            8080   { "HTTP alternativo" }
            8443   { "HTTPS alternativo" }
            27017  { "MongoDB" }
            5900   { "VNC" }
            1433   { "SQL Server" }
            default { "Serviço desconhecido" }
        }

        $status = if ($resultado.TcpTestSucceeded) {'ABERTA'} else {'FECHADA'}
        $corStatus = if ($status -eq 'ABERTA') {'Green'} else {'Red'}

        Write-Host "`n=== Resultados ===" -ForegroundColor Cyan
        Write-Host "Endereco: $($resultado.RemoteAddress)" -ForegroundColor Green
        Write-Host "Porta: $porta" -ForegroundColor Green
        Write-Host "Status: $status" -ForegroundColor $corStatus
        Write-Host "Servico: $servico" -ForegroundColor Green
        Write-Host "Latencia: $($resultado.PingReplyDetails.RoundtripTime)ms" -ForegroundColor Green
        Write-Host "Interface: $($resultado.InterfaceAlias)" -ForegroundColor Green

        # Banner Grabbing se a porta estiver aberta
        if ($resultado.TcpTestSucceeded) {
                Write-Host "`nObtendo informacoes da pagina HTTP..." -ForegroundColor DarkCyan
                $info = Get-Banner -ip $ip -porta $porta

                Write-Host "`n--- Informacoes HTTP ---" -ForegroundColor Cyan
                Write-Host "URL           : $($info.URL)" -ForegroundColor Gray
                Write-Host "Status HTTP   : $($info.StatusCode) $($info.StatusDesc)" -ForegroundColor Gray
                Write-Host "Titulo        : $($info.Titulo)" -ForegroundColor Gray
                Write-Host "Servidor      : $($info.Server)" -ForegroundColor Gray
                Write-Host "Tipo Conteudo : $($info.ContentType)" -ForegroundColor Gray
                Write-Host "X-Powered-By  : $($info.XPoweredBy)" -ForegroundColor Gray
                Write-Host "Cookies       : $($info.Cookies)" -ForegroundColor Gray
                Write-Host "robots.txt    : $($info.Robots)" -ForegroundColor Gray
                Write-Host "Favicon SHA1  : $($info.FaviconHash)" -ForegroundColor Gray

                if ($info.Links.Count -gt 0) {
                    Write-Host "`nLinks encontrados:" -ForegroundColor DarkGray
                    $info.Links | ForEach-Object { Write-Host "- $_" -ForegroundColor DarkGray }
                }

        }

        Write-Host "`nFim da verificacao." -ForegroundColor Cyan
    }

 
    function Pingar-Portas-Comuns-Ip {
        <#
        .SYNOPSIS
            Varre as 100 portas mais comuns de um IP e mostra as que estão abertas.
        .DESCRIPTION
            Realiza um scan rápido nas portas mais utilizadas, mostrando resultados em tempo real
            com informações de serviços conhecidos e tempo de execução.
        .EXAMPLE
            Pingar-Portas-Comuns-Ip
        #>

        # Configuração inicial
        Write-Host "`n=== Scan das Portas Mais Comuns ===" -ForegroundColor Cyan
        Write-Host "`nObs: Esta acao varre as 100 portas mais comuns" -ForegroundColor Yellow

        # Validação do IP
        do {
            $ip = Read-Host "`nDigite o IP (alvo)"
            if (-not (Validar-IP $ip)) {
                Write-Host "`nEndereco IP invalido. Tente novamente." -ForegroundColor Red
                Return
            }
        } while (-not (Validar-IP $ip))

        Write-Host "`nIniciando varredura nas portas mais comuns em $ip ..." -ForegroundColor Cyan
        $inicio = Get-Date

        # Lista de portas e serviços melhorada
        $portasEServicos = @(
            [PSCustomObject]@{Porta=20; Servico="FTP Data"},
            [PSCustomObject]@{Porta=21; Servico="FTP Control"},
            [PSCustomObject]@{Porta=22; Servico="SSH"},
            [PSCustomObject]@{Porta=23; Servico="Telnet"},
            [PSCustomObject]@{Porta=25; Servico="SMTP"},
            [PSCustomObject]@{Porta=53; Servico="DNS"},
            [PSCustomObject]@{Porta=67; Servico="DHCP Server"},
            [PSCustomObject]@{Porta=68; Servico="DHCP Client"},
            [PSCustomObject]@{Porta=69; Servico="TFTP"},
            [PSCustomObject]@{Porta=80; Servico="HTTP"},
            [PSCustomObject]@{Porta=110; Servico="POP3"},
            [PSCustomObject]@{Porta=123; Servico="NTP"},
            [PSCustomObject]@{Porta=135; Servico="RPC"},
            [PSCustomObject]@{Porta=137; Servico="NetBIOS Name"},
            [PSCustomObject]@{Porta=138; Servico="NetBIOS Datagram"},
            [PSCustomObject]@{Porta=139; Servico="NetBIOS Session"},
            [PSCustomObject]@{Porta=143; Servico="IMAP"},
            [PSCustomObject]@{Porta=161; Servico="SNMP"},
            [PSCustomObject]@{Porta=162; Servico="SNMP Trap"},
            [PSCustomObject]@{Porta=389; Servico="LDAP"},
            [PSCustomObject]@{Porta=443; Servico="HTTPS"},
            [PSCustomObject]@{Porta=445; Servico="SMB"},
            [PSCustomObject]@{Porta=465; Servico="SMTPS"},
            [PSCustomObject]@{Porta=500; Servico="IPSec"},
            [PSCustomObject]@{Porta=587; Servico="SMTP Submission"},
            [PSCustomObject]@{Porta=636; Servico="LDAPS"},
            [PSCustomObject]@{Porta=993; Servico="IMAPS"},
            [PSCustomObject]@{Porta=995; Servico="POP3S"},
            [PSCustomObject]@{Porta=1025; Servico="MS RPC"},
            [PSCustomObject]@{Porta=1433; Servico="SQL Server"},
            [PSCustomObject]@{Porta=1434; Servico="SQL Monitor"},
            [PSCustomObject]@{Porta=1701; Servico="L2TP"},
            [PSCustomObject]@{Porta=1723; Servico="PPTP"},
            [PSCustomObject]@{Porta=2049; Servico="NFS"},
            [PSCustomObject]@{Porta=3306; Servico="MySQL"},
            [PSCustomObject]@{Porta=3389; Servico="RDP"},
            [PSCustomObject]@{Porta=4500; Servico="IPSec NAT-T"},
            [PSCustomObject]@{Porta=5060; Servico="SIP"},
            [PSCustomObject]@{Porta=5061; Servico="SIP TLS"},
            [PSCustomObject]@{Porta=5432; Servico="PostgreSQL"},
            [PSCustomObject]@{Porta=5900; Servico="VNC"},
            [PSCustomObject]@{Porta=5985; Servico="WinRM HTTP"},
            [PSCustomObject]@{Porta=5986; Servico="WinRM HTTPS"},
            [PSCustomObject]@{Porta=6379; Servico="Redis"},
            [PSCustomObject]@{Porta=8080; Servico="HTTP Alt"},
            [PSCustomObject]@{Porta=8443; Servico="HTTPS Alt"},
            [PSCustomObject]@{Porta=8888; Servico="HTTP Alt2"},
            [PSCustomObject]@{Porta=9000; Servico="Hadoop NameNode"},
            [PSCustomObject]@{Porta=9090; Servico="Prometheus"},
            [PSCustomObject]@{Porta=9200; Servico="Elasticsearch"},
            [PSCustomObject]@{Porta=9300; Servico="Elasticsearch Cluster"},
            [PSCustomObject]@{Porta=10000; Servico="Webmin"},
            [PSCustomObject]@{Porta=11211; Servico="Memcached"},
            [PSCustomObject]@{Porta=27017; Servico="MongoDB"},
            [PSCustomObject]@{Porta=27018; Servico="MongoDB Shard"},
            [PSCustomObject]@{Porta=27019; Servico="MongoDB Router"}
        )

        $portasAbertas = [System.Collections.Generic.List[object]]::new()
        $contador = 0
        $totalPortas = $portasEServicos.Count

        # Barra de progresso
        foreach ($item in $portasEServicos) {
            $contador++
            $porcentagem = [math]::Round(($contador / $totalPortas) * 100, 2)
            
            Write-Progress -Activity "Varredura em andamento" `
                        -Status "Testando porta $($item.Porta) ($($item.Servico))" `
                        -PercentComplete $porcentagem `
                        -CurrentOperation "Portas testadas: $contador/$totalPortas"

            try {
                $teste = Test-NetConnection -ComputerName $ip -Port $item.Porta -WarningAction SilentlyContinue -InformationLevel Quiet
                if ($teste) {
                    $resultado = [PSCustomObject]@{
                        Porta = $item.Porta
                        Servico = $item.Servico
                        Status = "ABERTA"
                    }
                    $portasAbertas.Add($resultado)
                    Write-Host "[+] Porta $($item.Porta) ABERTA- Possivel:($($item.Servico))" -ForegroundColor Green
                } else {
                    Write-Host "[-] Porta $($item.Porta) fechada ($($item.Servico))" -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "[!] Erro ao verificar porta $($item.Porta): $_" -ForegroundColor Red
            }
        }

        # Resumo final
        $fim = Get-Date
        $duracao = ($fim - $inicio).TotalSeconds
        Write-Host "`n=== Resumo Final ===" -ForegroundColor Cyan

        if ($portasAbertas.Count -gt 0) {
            Write-Host "`nTotal de portas abertas encontradas: $($portasAbertas.Count)" -ForegroundColor Green
            Write-Host "`nDetalhes das portas abertas:" -ForegroundColor Yellow
            $portasAbertas | Sort-Object Porta | Format-Table -AutoSize -Property Porta, Servico, Status | Out-Host
        } else {
            Write-Host "Nenhuma porta aberta detectada." -ForegroundColor Yellow
        }

        Write-Host "`nTempo total: $([math]::Round($duracao, 2)) segundos" -ForegroundColor DarkCyan
        Write-Host "`nVarredura concluida." -ForegroundColor Cyan
    }


    do {
        Show-Menu
        $choice = Read-Host "Escolha um numero de ( 1 - 6 )"

        switch ($choice) {
            1 { Pingar-Ip }
            2 { Criar-Lista }
            3 { Varredura-IP }
            4 { Pingar-Todas-Portas-Ip }
            5 { Pingar-Portas-Comuns-Ip }
            6 { Pingar-Porta-Especifica }
            0 { Write-Host "Voltando ao menu principal..." -ForegroundColor Yellow; break }
            default { Write-Host "`nOpcao invalida. Escola um numero entre 1 a 6." -ForegroundColor Yellow }
        }

        if ($choice -ne 0) {
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Yellow
            $null = Read-Host
        }
    } while ($choice -ne 0)
}

function Busca-Por-DNS {
        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
        }

        # === Funcoes ===
        function ScanHeaders {
            param ([string]$url)
            try {
                Write-Host "`n Escaneando Headers..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Method Head -Headers $headers -ErrorAction Stop
                Write-Host "`n O servidor roda:" -ForegroundColor Green
                $response.Headers.Server
            } catch {
                Write-Host "`nErro ao buscar headers: $_" -ForegroundColor Red
            }
        }

        function ScanOptions {
            param ([string]$url)
            try {
                Write-Host "`n Verificando metodos HTTP suportados..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Method Options -Headers $headers -ErrorAction Stop
                Write-Host "`n Metodos permitidos pelo servidor:" -ForegroundColor Green
                $response.Headers.Allow
            } catch {
                Write-Host "`nErro ao buscar metodos OPTIONS: $_" -ForegroundColor Red
            }
        }

        function ScanLinks {
            param ([string]$url)
            try {
                Write-Host "`n Procurando links na pagina..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                Write-Host "`n Links encontrados:" -ForegroundColor Green
                $response.Links.Href | Select-String http
            } catch {
                Write-Host "`nErro ao buscar links: $_" -ForegroundColor Red
            }
        }

        function ScanHTML {
            param ([string]$url)
            try {
                Write-Host "`n Obtendo codigo-fonte do HTML..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                Write-Host "`n Codigo HTML recebido:" -ForegroundColor Green
                Write-Host $response.Content.Substring(0, 500) # Exibe os primeiros 500 caracteres
            } catch {
                Write-Host "`nErro ao obter o HTML: $_" -ForegroundColor Red
            }
        }

        function ScanTech {
            param ([string]$url)
            try {
                Write-Host "`n Detectando tecnologias utilizadas..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                if ($response.Headers["x-powered-by"]) {
                    Write-Host "`n Tecnologia detectada:" -ForegroundColor Green
                    $response.Headers["x-powered-by"]
                } else {
                    Write-Host "Nenhuma tecnologia detectada nos headers."
                }
            } catch {
                Write-Host "`nErro ao buscar tecnologias: $_" -ForegroundColor Red
            }
        }

        function ScanStatusCode {
            param ([string]$url)
            try {
                Write-Host "`n Obtendo codigo de status HTTP..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                Write-Host "`n Status Code:" -ForegroundColor Green
                $response.StatusCode
            } catch {
                Write-Host "`nErro ao obter Status Code: $_" -ForegroundColor Red
            }
        }

        function ScanTitle {
            param ([string]$url)
            try {
                Write-Host "`n Obtendo titulo da pagina..." -ForegroundColor Cyan
                $response = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
                if ($response.ParsedHtml.title) {
                    Write-Host "`n Titulo da pagina:" -ForegroundColor Green
                    $response.ParsedHtml.title
                } else {
                    Write-Host "`nNenhum titulo encontrado."
                }
            } catch {
                Write-Host "`nErro ao obter titulo da pagina: $_" -ForegroundColor Red
            }
        }

        function ScanRobotsTxt {
            param ([string]$url)
            try {
                Write-Host "`n Procurando robots.txt..." -ForegroundColor Cyan
                $robotsUrl = "$url/robots.txt"
                $response = Invoke-WebRequest -Uri $robotsUrl -Headers $headers -ErrorAction Stop
                Write-Host "`n Conteudo do robots.txt:" -ForegroundColor Green
                Write-Host $response.Content
            } catch {
                Write-Host "`nErro ao buscar robots.txt: $_" -ForegroundColor Red
            }
        }

        function ScanSitemap {
            param ([string]$url)
            try {
                Write-Host "`n Verificando sitemap.xml..." -ForegroundColor Cyan
                $sitemapUrl = "$url/sitemap.xml"
                $response = Invoke-WebRequest -Uri $sitemapUrl -Headers $headers -ErrorAction Stop
                Write-Host "`n Sitemap encontrado:" -ForegroundColor Green
                Write-Host $response.Content.Substring(0, 500)
            } catch {
                Write-Host "`nErro ao buscar sitemap.xml: $_" -ForegroundColor Red
            }
        }

        function ScanPorts {
            param ([string]$host)
            $ports = @(21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080)
            Write-Host "`n Escaneando portas comuns..." -ForegroundColor Cyan
            foreach ($port in $ports) {
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $tcp.Connect($host, $port)
                    Write-Host "Porta $port aberta!" -ForegroundColor Green
                    $tcp.Close()
                } catch {
                    Write-Host "Porta $port fechada."
                }
            }
        }
        
        function RunAllScans {
            param ([string]$url)

            Write-Host "`n=== Iniciando todas as verificacoes para a URL: $url ===`n" -ForegroundColor Magenta

            Write-Host "`n=== 1. Captura Headers do Servidor ===" -ForegroundColor Magenta
            ScanHeaders -url $url

            Write-Host "`n=== 2. Descobre os Metodos HTTP Permitidos ===" -ForegroundColor Magenta
            ScanOptions -url $url

            Write-Host "`n=== 3. Lista os Links Encontrados no HTML ===" -ForegroundColor Magenta
            ScanLinks -url $url

            Write-Host "`n=== 4. Obtem Codigo-Fonte do HTML ===" -ForegroundColor Magenta
            ScanHTML -url $url

            Write-Host "`n=== 5. Detecta Tecnologias Utilizadas ===" -ForegroundColor Magenta
            ScanTech -url $url

            Write-Host "`n=== 6. Obtem Codigo de Status HTTP ===" -ForegroundColor Magenta
            ScanStatusCode -url $url

            Write-Host "`n=== 7. Obtem o <title> da Pagina ===" -ForegroundColor Magenta
            ScanTitle -url $url

            Write-Host "`n=== 8. Verifica o arquivo robots.txt ===" -ForegroundColor Magenta
            ScanRobotsTxt -url $url

            Write-Host "`n=== 9. Verifica se o site possui um Sitemap ===" -ForegroundColor Magenta
            ScanSitemap -url $url

            Write-Host "`n=== Todas as verificacoes foram conclui­das! ===`n" -ForegroundColor Magenta
            Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
            $null = Read-Host
        }

        while ($true) {
            Clear-Host
            Write-Host "`n`n`n`n`n`n+==================================================+" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||         === Menu de busca por DNS ===          ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "+==================================================+" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      1. Captura Headers do Servidor            ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      2. Descobre os Metodos HTTP Permitidos    ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      3. Lista os Links Encontrados no HTML     ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      4. Obtem Codigo-Fonte do HTML             ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      5. Detecta Tecnologias Utilizadas         ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      6. Obtem Codigo de Status HTTP            ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      7. Obtem o <title> da Pagina              ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      8. Verifica o arquivo robots.txt          ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      9. Verifica se o site possui um Sitemap   ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      10. Faz um Scan Rapido das Portas Comuns  ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      11. Rodar todas opcoes (1 a 9)            ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "||      12. Voltar para o Menu Principal          ||" -ForegroundColor Magenta
            Write-Host "||                                                ||" -ForegroundColor Magenta
            Write-Host "+==================================================+" -ForegroundColor Magenta
            Write-Host "`n`n"

            $opcao = Read-Host "`nEscolha uma opcao (1-12)"
        
            switch ($opcao) {
                1 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanHeaders -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                2 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanOptions -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                3 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanLinks -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                4 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanHTML -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                5 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanTech -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                6 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanStatusCode -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                7 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanTitle -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                8 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanRobotsTxt -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                9 {
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    ScanSitemap -url $url
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                10 {
                    $host = Read-Host "`nDigite o host ou IP (ex: exemplo.com ou 192.168.1.1)"
                    ScanPorts -host $host
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
                11{
                    $url = Read-Host "`nDigite a URL do site (ex: https://exemplo.com)"
                    RunAllScans -url $url
                }
                12 {
                    Write-Host "`nSaindo..." -ForegroundColor Magenta
                    return
                }
                default {
                    Write-Host "`nOpcao invalida. Escolha um numero entre 1 a 12." -ForegroundColor Magenta
                    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Magenta
                    $null = Read-Host
                }
            }
        }

}
        
while ($true) {
    Clear-Host
    Write-Host "`n`n`n`n`n`n+====================================================================+" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                       === Menu Principal ===                     ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "+====================================================================+" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                 1. Mostrar informacoes do computador             ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                 2. Informacoes avancadas de Usuarios             ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                 3. Servicos e Portas ( UDP / TCP )               ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                 4. WMap                                          ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                 5. DNS Requests                                  ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "||                 0. Sair                                          ||" -ForegroundColor Green
    Write-Host "||                                                                  ||" -ForegroundColor Green
    Write-Host "+====================================================================+" -ForegroundColor Green

    $opcao = Read-Host "`nEscolha uma das opcoes de 1 a 5"
    
    switch ($opcao){
        1{
          Show-ComputerInfo
        }
        2{
          Show-UserInfo
         }
        3 {
          Servicos
        }
        4 {
          Wmap
        }
        5 {
          Busca-Por-DNS
        }
        0 {
          Write-Host "`n+====================================================================+" -ForegroundColor Green
          Write-Host "||                 Obrigado por testar R-DiasWIn                    ||" -ForegroundColor Green
          Write-Host "+====================================================================+" -ForegroundColor Green
          return
        }
        default {
          Write-Host "`nOpcao invalida. Escolha um numero entre 1 a 7." -ForegroundColor Yellow
          Write-Host "`nPressione Enter para continuar..." -ForegroundColor Yellow
          $null = Read-Host
        }
    }
}
