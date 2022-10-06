start-sleep -s 300
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

$eth1PvtIP = ""
$eth2PvtIP = ""
$sleepTime = 60

function getLogAnalyticsInfo {
    param (
        $resourceGroupName,
        $vmssName
    )
    # get all workspaces present in same resource group
    $workspaces = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName

    # vm name suffix
    $vmSuffix = $vmssName.Split('-')[-1]

    # initialize workspace name
    $workspaceName = $null

    # get workspace name
    foreach ($workspace in $workspaces){
        $wSuffix = $workspace.Name.Split('-')[-1]
        if ($wSuffix -eq $vmSuffix){
            $workspaceName = $workspace.Name
            break
        }
    }

    if ($null -eq $workspaceName) {
        Write-Output "Log Analytics Workspace not found in resource group"
        return
    }

    # get log analytics workspace id
    $workspaceID = Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $resourceGroupName

    # get log analytics workspace primary key
    $key = Get-AzOperationalInsightsWorkspaceSharedKey -Name $workspaceName -ResourceGroupName $resourceGroupName

    return $workspaceID.CustomerId, $key.PrimarySharedKey
}

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
        $AuthorizationToken,
        $pubLBPubIP
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
        $AuthorizationToken,
        $gwlbPvtIP
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
    `n          `"ip-address`":`"$gwlbPvtIP`",
    `n          `"vni-list`": [
    `n            {
    `n              `"segment`":800
    `n            }
    `n          ]
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
    return $response
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
        $AuthorizationToken,
        $mgmtNextHop,
        $eth1NextHop,
        $pubLBPubIP
    ) 
    
    $Url = -join($BaseUrl, "/ip/route/rib")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

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
    
}

function LifRoute {
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    
    $Url = -join($BaseUrl, "/ip/route/source/lif")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"lif-list`": [
    `n    {
    `n      `"ifname`":`"clean`",
    `n      `"nexthop-ip`":`"172.16.1.2`"
    `n    },
    `n    {
    `n      `"ifname`":`"dirty`",
    `n      `"nexthop-ip`":`"172.16.2.2`"
    `n    }
    `n  ]
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body
    
}

function SystemDDOS {
    param (
        $BaseUrl,
        $AuthorizationToken
    )
    
    $Url = -join($BaseUrl, "/system")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    $body = "{
    `n  `"system`": {
    `n    `"ddos-attack`":1,
    `n    `"ddos-log`":1
    `n  }
    `n}"

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers -Body $body

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
        $vthunderBaseUrl,
        $AuthorizationToken
    )
    $Url = -join($BaseUrl, "/write/memory")
 
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers

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
        $vthunderBaseUrl,
        $AuthorizationToken
    )
    
    $Url = -join($BaseUrl, "/reboot")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $Url -Method 'POST' -Headers $headers
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
        $AuthorizationToken,
        $mgmtNextHop,
        $eth1NextHop,
        $gwlbPvtIP,
        $pubLBPubIP
    )

    InterfaceEthernet -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    InterfaceLif -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DDOSHealth -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DDOSInterfaceIP -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    OverlayTunnelVTEP -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken -gwlbPvtIP $gwlbPvtIP

    DDOSProtection -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    DDOSDstZone -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken -pubLBPubIP $pubLBPubIP

    IPRouteConfig -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken -mgmtNextHop $mgmtNextHop -eth1NextHop $eth1NextHop -pubLBPubIP $pubLBPubIP

    SystemDDOS -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    # LifRoute -BaseUrl $vthunderBaseUrl -AuthorizationToken $AuthorizationToken

    return "vTPS Configuration Applied"
}

function getNextHop {
    #Get list of subnets from vnet
    $mgmtNextHop = ""
    $eth1NextHop = ""
    $vNet = Get-AzVirtualNetwork -Name $vNetName -ResourceGroupName $resourceGroupName
    foreach ( $subnet in $vNet.Subnets){
        if ($subnet.name -eq $mgmtSubnetName){
            $mgmtAddPref = $subnet.AddressPrefix[0]
            $splitedIP = $mgmtAddPref.split(".")
            [string]$nextHopNum = [int]$splitedIP[-1].split("/")[0] += 1
            $mgmtNextHop = -join($splitedIP[0], ".", $splitedIP[1], ".", $splitedIP[2], ".", $nextHopNum)
            continue
        }
        if ($subnet.name -eq $eth1SubnetName){
            $eht1AddPref = $subnet.AddressPrefix[0]
            $splitedIP = $eht1AddPref.split(".")
            [string]$nextHopNum = [int]$splitedIP[-1].split("/")[0] += 1
            $eth1NextHop = -join($splitedIP[0], ".", $splitedIP[1], ".", $splitedIP[2], ".", $nextHopNum)
        }
    }
    return $mgmtNextHop, $eth1NextHop
}

function InsertLogAnalyticsInfo {
    param (
        $vthunderBaseUrl,
        $AuthorizationToken,
        $customerId,
        $primarySharedKey,
        $vmId,
        $resourceGroupName,
        $publicIp
    )
    $url = -join($vthunderBaseUrl, "/cloud-services")
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", -join("A10 ", $AuthorizationToken))

    # creating array list
    $cloudProviderList = New-Object System.Collections.ArrayList

    # creating resource information object
    $resourceInfo = @{
        "cloud-provider" = "azure"
              "log-analytics" = 1
              "workspace-id" = $customerId
              "primary-key" = $primarySharedKey
              "source-resource-id" = $vmId
              "source-ip" = $publicIp
              "action" = "enable"
    }

    # append resource info object into list
    [void]$cloudProviderList.Add($resourceInfo)

    $body = @{
        "cloud-services" = @{
          "cloud-provider-list" = $cloudProviderList
          }
      }
    
    $body = $body | ConvertTo-Json -Depth 6
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $response = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $headers -Body $body
    if ($null -eq $response) {
        Write-Error "Failed to insert log analytics information into vTPS instance $publicIp"
    } else {
        Write-Output "Inserted log analytics information into vTPS instance $publicIp"
    }
}

#Get list of vm from vmss
$vmss = Get-AzVmssVM -ResourceGroupName $resourceGroupName -VMScaleSetName $vTPSScaleSetName

# get log analytics workspace information
$customerId, $primarySharedKey = getLogAnalyticsInfo -resourceGroupName $resourceGroupName -vmssName $vTPSScaleSetName

$pubIpList = New-Object System.Collections.ArrayList
$eth1PvtIPList = New-Object System.Collections.ArrayList
$eth2PvtIPList = New-Object System.Collections.ArrayList
$vmNameList = New-Object System.Collections.ArrayList
$vmIDList = New-Object System.Collections.ArrayList


# Get private and public ip address of each vm
foreach($vm in $vmss) {
    $vTPSPubIP = " "

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

    if($vTPSPubIP -eq "Not Assigned" -or $vTPSPubIP -eq " "){
        continue
    }

    [void]$pubIpList.Add($vTPSPubIP)
    [void]$eth1PvtIPList.Add($eth1PvtIP)
    [void]$eth2PvtIPList.Add($eth2PvtIP)
    [void]$vmNameList.Add($vm.Name)
    [void]$vmIDList.Add($vm.Id)
}

# check if all list lengths are equal
if ($pubIpList.Count -ne $eth1PvtIPList.Count -or $pubIpList.Count -ne $eth2PvtIPList.Count -or $pubIpList.Count -ne $vmNameList.Count -or $pubIpList.Count -ne $vmIDList.Count) {
    Write-Error "Failed to fetch vtps instances public ip, data interfaces, name and resource id information" -ErrorAction Stop
}

$gwlb = Get-AzLoadBalancer -Name $gwLBName -ResourceGroupName $resourceGroupName
$gwlbPvtIP = $gwlb.FrontendIpConfigurations[0].PrivateIpAddress

$mgmtNextHop, $eth1NextHop = getNextHop

$newPubIPList = ""
for($i = 0; $i -lt $pubIpList.Count; $i++){

    $vTPSPubIP = $pubIpList[$i]
    $eth1PvtIP = $eth1PvtIPList[$i]
    $eth2PvtIP = $eth2PvtIPList[$i]
    $vmName = $vmNameList[$i]
    $vmID = $vmIDList[$i]
    
    if ($vTPSPubIP -eq ""){
        continue
    }
    
    $configStatus = "true"
    if(-Not $vTPSPubIPList.Contains($vTPSPubIP)){
        Write-Output $vTPSPubIP
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
                $responce = DNSConfig -BaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken
                if ($null -eq $responce){
                    start-sleep -s $sleepTime
                    $count += 1
                    $configStatus = "false"
                    Write-Output "Got the AuthorizationToken, Wating For vTPS Config State" $count
                    continue
                }
                ConfigvTPS -vthunderBaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken -mgmtNextHop $mgmtNextHop -eth1NextHop $eth1NextHop -gwlbPvtIP $gwlbPvtIP -pubLBPubIP $pubLBPubIP
                # # get and save log analytics information in vthunder instance
                # InsertLogAnalyticsInfo -vthunderBaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken -vmName $vmName -vmId $vmID -resourceGroupName $resourceGroupName -publicIp $vTPSPubIP -vmssName $vTPSScaleSetName -customerId $customerId -primarySharedKey $primarySharedKey
                # save configurations
                WriteMemory -vthunderBaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken
                # reboot vtps instance
                Reboot -vthunderBaseUrl $BaseUrl -AuthorizationToken $AuthorizationToken
                $configStatus = "true"
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