start-sleep -s 200

$appId = Get-AutomationVariable -Name appId
$secret = Get-AutomationVariable -Name secret
$tenantId = Get-AutomationVariable -Name tenantId
$resourceGroupName = Get-AutomationVariable -Name resourceGroupName
$vTPSScaleSetName = Get-AutomationVariable -Name vTPSScaleSetName
$gwLBName = Get-AutomationVariable -Name gwLBName
$pubLBPubIP = Get-AutomationVariable -Name pubLBPubIP
$vNetName = Get-AutomationVariable -Name vNetName
$mgmtSubnetName = Get-AutomationVariable -Name mgmtSubnetName
$eth1SubnetName = Get-AutomationVariable -Name eth1SubnetName
$vTPSPubIPs = Get-AutomationVariable -Name vTPSPubIPList
$vTPSUserName = Get-AutomationVariable -Name vTPSUserName
$vTPSPassword = Get-AutomationVariable -Name vTPSPassword
$vTPSPubIPList = $vTPSPubIPs.split(" ")

$secureStringPwd = $secret | ConvertTo-SecureString -AsPlainText -Force
$pscredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appId, $secureStringPwd
Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantId

$gwlb = Get-AzLoadBalancer -Name $gwLBName -ResourceGroupName $resourceGroupName

$mgmtNextHop = ""
$eth1NextHop = ""
$eth1PvtIP = ""
$eth2PvtIP = ""
$gwlbPvtIP = $gwlb.FrontendIpConfigurations[0].PrivateIpAddress
$sleepTime = 60

#Get list of subnets from vnet
$vNet = Get-AzVirtualNetwork -Name $vNetName -ResourceGroupName $resourceGroupName
foreach ( $subnet in $vNet.Subnets){
    if ($subnet.name -eq $mgmtSubnetName){
        $mgmtAddPref = $subnet.AddressPrefix[0]
        $splitedIP = $mgmtAddPref.split(".")
        [string]$nextHopNum = [int]$splitedIP[-1].split("/")[0] += 1
        $mgmtNextHop = -join($splitedIP[0], ".", $splitedIP[1], ".", $splitedIP[2], ".", $nextHopNum)
        Write-Output $mgmtNextHop
        continue
    }
    if ($subnet.name -eq $eth1SubnetName){
        $eht1AddPref = $subnet.AddressPrefix[0]
        $splitedIP = $eht1AddPref.split(".")
        [string]$nextHopNum = [int]$splitedIP[-1].split("/")[0] += 1
        $eth1NextHop = -join($splitedIP[0], ".", $splitedIP[1], ".", $splitedIP[2], ".", $nextHopNum)
        Write-Output $eth1NextHop
    }
}

#Get list of vm from vmss
$vmss = Get-AzVmssVM -ResourceGroupName $resourceGroupName -VMScaleSetName $vTPSScaleSetName

function GetAuthToken {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .OUTPUTS
        Authorization token
        .DESCRIPTION
        Function to get Authorization token
        AXAPI: /axapi/v3/auth
    #>
    param (
        $BaseUrl
    )
    # AXAPI Auth url
    $Url = -join($BaseUrl, "/auth")
    # AXAPI header
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    # AXAPI Auth url json body
    $Body = "{
    `n    `"credentials`": {
    `n        `"username`": `"$vTPSUserName`",
    `n        `"password`": `"$vTPSPassword`"
    `n    }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    # Invoke Auth url
    $Response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    # fetch Authorization token from response
    $AuthorizationToken = $Response.authresponse.signature
    return $AuthorizationToken
}

function InterfaceEthernet {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to apply configurations
        AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Urleth1 = -join($BaseUrl, "/interface/ethernet/1")
    $headerseth1 = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headerseth1.Add("Content-Type", "application/json")
    $headerseth1.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $bodyeth1 = "{
    `n  `"ethernet`": {
    `n    `"ifnum`": 1,
    `n    `"action`": `"enable`",
    `n    `"ddos`": {
    `n        `"inside`":1
    `n      },
    `n      `"ip`": {
    `n        `"address-list`": [
    `n          {
    `n            `"ipv4-address`":`"$eth1PvtIP`",
    `n            `"ipv4-netmask`":`"255.255.255.0`"
    `n          }
    `n        ]
    `n      }
    `n  }
    `n}"
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $responseeth1 = Invoke-RestMethod -Uri $Urleth1 -Method 'POST' -Headers $headerseth1 -Body $bodyeth1
    $responseeth1 | ConvertTo-Json
    
    $Urleth2 = -join($BaseUrl, "/interface/ethernet/2")
    $headerseth2 = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headerseth2.Add("Content-Type", "application/json")
    $headerseth2.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $bodyeth2 = "{
    `n  `"ethernet`": {
    `n    `"ifnum`": 2,
    `n    `"action`": `"enable`",
    `n    `"ddos`": {
    `n        `"outside`":1
    `n      },
    `n      `"ip`": {
    `n        `"address-list`": [
    `n          {
    `n            `"ipv4-address`":`"$eth2PvtIP`",
    `n            `"ipv4-netmask`":`"255.255.255.0`"
    `n          }
    `n        ]
    `n      }
    `n  }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response2 = Invoke-RestMethod -Uri $Urleth2 -Method 'POST' -Headers $headerseth2 -Body $bodyeth2
    $response2 | ConvertTo-Json
}

function InterfaceLif {
    <#
    .PARAMETER BaseUrl
    Base url of AXAPI
    .PARAMETER AuthorizationToken
    AXAPI authorization token
    .DESCRIPTION
    Function to apply configurations
    AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Url = -join($BaseUrl, "/interface/lif")

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"lif-list`": [
    `n    {
    `n      `"ifname`":`"clean`",
    `n      `"ip`": {
    `n        `"address-list`": [
    `n          {
    `n            `"ipv4-address`":`"172.16.2.1`",
    `n            `"ipv4-netmask`":`"255.255.255.252`"
    `n          }
    `n        ]
    `n      }
    `n    },
    `n    {
    `n      `"ifname`":`"dirty`",
    `n      `"ip`": {
    `n        `"address-list`": [
    `n          {
    `n            `"ipv4-address`":`"172.16.1.1`",
    `n            `"ipv4-netmask`":`"255.255.255.252`"
    `n          }
    `n        ]
    `n      }
    `n    }
    `n  ]
    `n}"
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    return $response
}

function DDOSHealth {
        <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to apply configurations
        AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Url = -join($BaseUrl, "/ddos/interface-http-health-check")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"interface-http-health-check`": {
    `n    `"enable`":`"enable`",
    `n    `"challenge-method`":`"javascript`"
    `n  }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

}

function DDOSInterfaceIP {
    <#
    .PARAMETER BaseUrl
    Base url of AXAPI
    .PARAMETER AuthorizationToken
    AXAPI authorization token
    .DESCRIPTION
    Function to apply configurations
    AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Url = -join($BaseUrl, "/ddos/dst/interface-ip")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
        `n  `"interface-ip-list`": [
        `n    {
        `n      `"addr`":`"$eth1PvtIP`",
        `n      `"port-list`": [
        `n        {
        `n          `"port-num`":80,
        `n          `"protocol`":`"http-probe`"
        `n        }
        `n      ]
        `n    },
        `n    {
        `n      `"addr`":`"$eth2PvtIP`",
        `n      `"port-list`": [
        `n        {
        `n          `"port-num`":80,
        `n          `"protocol`":`"http-probe`"
        `n        }
        `n      ]
        `n    }
        `n  ]
        `n}"
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

}

function DDOSProtection {
    <#
    .PARAMETER BaseUrl
    Base url of AXAPI
    .PARAMETER AuthorizationToken
    AXAPI authorization token
    .DESCRIPTION
    Function to apply configurations
    AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Url = -join($BaseUrl, "/ddos/protection")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"protection`": {
    `n    `"toggle`":`"enable`"
    `n  }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json
    
}

function DDOSDstZone {
    <#
    .PARAMETER BaseUrl
    Base url of AXAPI
    .PARAMETER AuthorizationToken
    AXAPI authorization token
    .DESCRIPTION
    Function to apply configurations
    AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Url = -join($BaseUrl, "/ddos/dst/zone")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
        `n  `"zone-list`": [
        `n    {
        `n      `"zone-name`":`"z1`",
        `n      `"operational-mode`":`"monitor`",
        `n      `"ip`": [
        `n        {
        `n          `"ip-addr`":`"$pubLBPubIP`"
        `n        }
        `n      ],
        `n      `"port`": {
        `n        `"zone-service-other-list`": [
        `n          {
        `n            `"port-other`":`"other`",
        `n            `"protocol`":`"tcp`"
        `n          },
        `n          {
        `n            `"port-other`":`"other`",
        `n            `"protocol`":`"udp`"
        `n          }
        `n        ]
        `n      }
        `n    }
        `n  ]
        `n}
        `n"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

}

function OverlayTunnelVTEP {
    <#
    .PARAMETER BaseUrl
    Base url of AXAPI
    .PARAMETER AuthorizationToken
    AXAPI authorization token
    .DESCRIPTION
    Function to apply configurations
    AXAPI: /axapi/v3/interface/ethernet/1
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )

    $Url = -join($BaseUrl, "/overlay-tunnel/vtep")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"vtep-list`": [
    `n    {
    `n      `"id`":1,
    `n      `"encap`":`"vxlan`",
    `n      `"dest-port`":10801,
    `n      `"local-ip-address`": {
    `n        `"ip-address`":`"$eth2PvtIP`",
    `n        `"vni-list`": [
    `n          {
    `n            `"segment`":801,
    `n            `"lif`":`"dirty`"
    `n          }
    `n        ]
    `n      },
    `n      `"remote-ip-address-list`": [
    `n        {
    `n          `"ip-address`":`"$gwlbPvtIP`",
    `n          `"vni-list`": [
    `n            {
    `n              `"segment`":801
    `n            }
    `n          ]
    `n        }
    `n      ],
    `n      `"host-list`": [
    `n        {
    `n          `"ip-addr`":`"172.16.1.2`",
    `n          `"overlay-mac-addr`":`"aaaa.aaaa.aaaa`",
    `n          `"vni`":801,
    `n          `"remote-vtep`":`"$gwlbPvtIP`"
    `n        }
    `n      ]
    `n    },
    `n    {
    `n      `"id`":2,
    `n      `"encap`":`"vxlan`",
    `n      `"dest-port`":10800,
    `n      `"local-ip-address`": {
    `n        `"ip-address`":`"$eth1PvtIP`",
    `n        `"vni-list`": [
    `n          {
    `n            `"segment`":800,
    `n            `"lif`":`"clean`"
    `n          }
    `n        ]
    `n      },
    `n      `"remote-ip-address-list`": [
    `n        {
    `n          `"ip-address`":`"$gwlbPvtIP`"
    `n        }
    `n      ],
    `n      `"host-list`": [
    `n        {
    `n          `"ip-addr`":`"172.16.2.2`",
    `n          `"overlay-mac-addr`":`"aaaa.aaaa.aaaa`",
    `n          `"vni`":800,
    `n          `"remote-vtep`":`"$gwlbPvtIP`"
    `n        }
    `n      ]
    `n    }
    `n  ]
    `n}
    `n"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json
}

function DNSConfig {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to save configurations on active partition
        AXAPI: /axapi/v3/active-partition
        AXAPI: /axapi/v3//write/memory
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    ) 
    
    $Url = -join($BaseUrl, "/ip/dns/primary")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $Headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"primary`": {
    `n    `"ip-v4-addr`":`"8.8.8.8`"
    `n  }
    `n}
    `n"
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

}

function IPRouteConfig {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to save configurations on active partition
        AXAPI: /axapi/v3/active-partition
        AXAPI: /axapi/v3//write/memory
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    ) 
    
    $Url = -join($BaseUrl, "/ip/route/rib")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $Headers.Add("Authorization", -join("A10 ", $AuthorizationToken))
    
    $body = "{
    `n  `"rib-list`": [
    `n    {
    `n      `"ip-dest-addr`":`"0.0.0.0`",
    `n      `"ip-mask`":`"/0`",
    `n      `"ip-nexthop-ipv4`": [
    `n        {
    `n          `"ip-next-hop`":`"$mgmtNextHop`"
    `n        }
    `n      ]
    `n    },
    `n    {
    `n      `"ip-dest-addr`":`"8.8.8.8`",
    `n      `"ip-mask`":`"/32`",
    `n      `"ip-nexthop-ipv4`": [
    `n        {
    `n          `"ip-next-hop`":`"$mgmtNextHop`"
    `n        }
    `n      ]
    `n    },
    `n    {
    `n      `"ip-dest-addr`":`"10.0.4.4`",
    `n      `"ip-mask`":`"/32`",
    `n      `"ip-nexthop-ipv4`": [
    `n        {
    `n          `"ip-next-hop`":`"$eth1NextHop`"
    `n        }
    `n      ]
    `n    },
    `n    {
    `n      `"ip-dest-addr`":`"$pubLBPubIP`",
    `n      `"ip-mask`":`"/32`",
    `n      `"ip-nexthop-ipv4`": [
    `n        {
    `n          `"ip-next-hop`":`"172.16.2.2`"
    `n        }
    `n      ]
    `n    }
    `n  ]
    `n}
    `n"
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

}

function WriteMemory {
    <#
        .PARAMETER BaseUrl
        Base url of AXAPI
        .PARAMETER AuthorizationToken
        AXAPI authorization token
        .DESCRIPTION
        Function to save configurations on active partition
        AXAPI: /axapi/v3/active-partition
        AXAPI: /axapi/v3//write/memory
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    $Url = -join($BaseUrl, "/write/memory")
 
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers
    $response | ConvertTo-Json

}

function Reboot {
    <#
    .PARAMETER BaseUrl
    Base url of AXAPI
    .PARAMETER AuthorizationToken
    AXAPI authorization token
    .DESCRIPTION
    Function to save configurations on active partition
    AXAPI: /axapi/v3/reboot
    #>
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    
    $Url = -join($BaseUrl, "/reboot")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers
    $response | ConvertTo-Json
    Write-Output "Reboot Done"
}

function ConfigvTPS {
    <#
    .PARAMETER vTPSPubIP
    vTPS Public IP
    .DESCRIPTION
    Function to configurations on active vTPS
    #>
    param (
        $vthunderBaseUrl,
        $AuthorizationToken
    )

    InterfaceEthernet -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken
    
    DDOSHealth -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DDOSInterfaceIP -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DDOSProtection -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DDOSDstZone -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    OverlayTunnelVTEP -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DNSConfig -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    IPRouteConfig -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    # Invoke WriteMemory
    WriteMemory -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    Reboot -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    return "Updated server information"
}


function getPublicIP {
    param(
        $vm
    )
    # get interface and check public ip address
    $mgmtInterfaceId = $vm.NetworkProfile.NetworkInterfaces[0].Id
    $eth1InterfaceId = $vm.NetworkProfile.NetworkInterfaces[1].Id
    $eth2InterfaceId = $vm.NetworkProfile.NetworkInterfaces[2].Id
    $mgmtInterfaceName = $mgmtInterfaceId.Split('/')[-1]
    $eth1InterfaceName = $eth1InterfaceId.Split('/')[-1]
    $eth2InterfaceName = $eth2InterfaceId.Split('/')[-1]
    $mgmtInterfaceConfig = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name $mgmtInterfaceName -VirtualMachineScaleSetName $vTPSScaleSetName -VirtualMachineIndex $vm.InstanceId
    $eth1InterfaceConfig = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name $eth1InterfaceName -VirtualMachineScaleSetName $vTPSScaleSetName -VirtualMachineIndex $vm.InstanceId
    $eth2InterfaceConfig = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name $eth2InterfaceName -VirtualMachineScaleSetName $vTPSScaleSetName -VirtualMachineIndex $vm.InstanceId
    
    $eth1PvtIP = $eth1InterfaceConfig.IpConfigurations[0].PrivateIpAddress
    $eth2PvtIP = $eth2InterfaceConfig.IpConfigurations[0].PrivateIpAddress
    
    $publicIpConfig =  Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -VirtualMachineScaleSetName $vTPSScaleSetName -NetworkInterfaceName $mgmtInterfaceConfig.name -IpConfigurationName $mgmtInterfaceConfig.IpConfigurations[0].Name -VirtualMachineIndex $vm.InstanceId
    $vTPSPubIP = $publicIpConfig.IpAddress
    return $vTPSPubIP, $eth1PvtIP, $eth2PvtIP
}

$newPubIPList = ""
# Get private and public ip address of each vm
foreach($vm in $vmss) {
    try {
        $vTPSPubIP, $eth1PvtIP, $eth2PvtIP = getPublicIP -vm $vm
    }
    catch {
           Write-Output "Catch the code"
           $pscredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appId, $secureStringPwd
           Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantId
           $vTPSPubIP, $eth1PvtIP, $eth2PvtIP = getPublicIP -vm $vm
    }

    if($vTPSPubIP -eq "Not Assigned"){
        continue
    }

    $configStatus = "true"
    if(-Not $vTPSPubIPList.Contains($vTPSPubIP)){
        Write-Output "Config the vTPS", $vTPSPubIP
        $count = 0
        $BaseUrl = -join("https://", $vTPSPubIP, "/axapi/v3")
        
        while($count -lt 15){
            $AuthorizationToken = GetAuthToken -BaseUrl $BaseUrl
            if ($null -eq $AuthorizationToken) {
                start-sleep -s $sleepTime
                $count += 1
                $configStatus = "false"
                Write-Output "Wating For vTPS Ready State" $count
            }
            else {
                $responce = InterfaceLif -BaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken
                Write-Output "InterfaceLif function output" 
                Write-Output $responce
                if ($null -eq $responce){
                    start-sleep -s $sleepTime
                    $count += 1
                    $configStatus = "false"
                    Write-Output "Wating For vTPS Ready State" $count
                    continue
                }
                ConfigvTPS -vthunderBaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken
                Break
            }
        }
    }
    if ($configStatus -eq "true"){
        $newPubIPList = -join($newPubIPList, $vTPSPubIP, " ")
    } 
}

Write-Output $newPubIPList
Set-AutomationVariable -Name "vTPSPubIPList" -Value $newPubIPList