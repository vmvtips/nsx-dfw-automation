$dfwrules = import-csv rules.csv
#[array]::Reverse($dfwrules)

function CheckIPAddress {
    param (
        [Parameter(Mandatory)][string]$IfIPaddress
    )
    $validipformat = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"
    $Checkstring = $IfIPaddress.Split("/")
    if ($Checkstring[0] -match $validipformat) {
        $resultip = $true
    }
    else {
        $resultip = $false
    }
    return $resultip
}
function CheckPort {
    param (
        [Parameter(Mandatory)][string]$Ifportnumber
    )
    $validportformat = "^\d+$"
    if ($Ifportnumber -match $validportformat) {
        $resultport = $true
    }
    else {
        $resultport = $false
    }
    return $resultport
}
function getnsxtgrouppath {
    param (
        [Parameter(Mandatory)][string]$nsxtgroupname
    )
    $nsxtsearch = Get-NsxtPolicyService -Name com.vmware.nsx_policy.search.query
    $nsxtsearchgroup = $nsxtsearch.list($nsxtgroupname).results
    if ($nsxtsearchgroup.count -eq 0) {
        $nsxtgrouppath = "invalid"
    }
    else {
        foreach($nsxtsearchresult in $nsxtsearchgroup){
            if ($nsxtsearchresult.resource_type -eq 'Group' -and $nsxtsearchresult.display_name -eq $nsxtgroupname) {
                $nsxtgrouppath = $nsxtsearchresult.path
            }
        }
    }
    return $nsxtgrouppath
}
function getnsxtservice {
    param (
        [Parameter(Mandatory)][string]$nsxtservicename
    )
    $nsxtsearch = Get-NsxtPolicyService -Name com.vmware.nsx_policy.search.query
    $nsxtsearchservice = $nsxtsearch.list($nsxtservicename).results
    if ($nsxtsearchservice.count -eq 0) {
        $nsxtservicepath = "invalid"
    }
    else {
        foreach($nsxtsvcresult in $nsxtsearchservice) {
            if ($nsxtsvcresult.resource_type -eq 'Service' -and $nsxtsvcresult.display_name -eq $nsxtservicename) {
                $nsxtservicepath = $nsxtsvcresult.path 
                break
            }
        }
    }
    return $nsxtservicepath
}

foreach ($dfwrule in $dfwrules) {
    $dfwsequencenumber = $dfwrule.RuleID
    $dfwportype = "TCP"
    $dfwruleaction = $dfwrule.Action
    $dfwsourceIPs = $dfwrule.SourceName
    $dfwdestinationIPs = $dfwrule.DestinationName
    #$dfwsourceports = ""
    #$sourceservicename = $dfwportype.toupper()
    $dfwdestports = $dfwrule.ServiceName
    #$dfwinterface = $dfwrule.interface
    $dfwpolicysectname = $dfwrule.SectionName
    $dfwrulename = $dfwrule.RuleName
    $dfwdirection = $dfwrule.Direction

    $dfwpolicyfirewallsvc = Get-NsxtPolicyService -Name com.vmware.nsx_policy.infra.domains.security_policies.rules
    $dfwrulespec = $dfwpolicyfirewallsvc.Help.patch.rule.Create()

    #Check Source IP or group name and add them to firewall spec

    if ($dfwsourceIPs -ne "") {
        $dfwrulespec.source_groups = @("")
        $tmp = @()
        $dfwsourceIP = $dfwsourceIPs.split(";")
        #$dfwrulename += $dfwsourceIP[0].Replace("/","-")
        foreach ($srcip in $dfwsourceIP) {
            $ifipaddr = CheckIPAddress -IfIPaddress $srcip
            if ($ifipaddr) {
                $tmp += @("$srcip")
            }
            else {
                if ($srcip -eq "") {
                }
                elseif ($srcip.toupper() -eq "ANY") {
                    $tmp = @("ANY")
                    break
                }
                else {
                    $checknsxtgroup = getnsxtgrouppath -nsxtgroupname $srcip
                    if ($checknsxtgroup -eq "invalid") {
                        Write-Host "Invalid Group Name - " $srcip
                        break
                    }
                    else {
                        $tmp += @($checknsxtgroup)
                    }
                }
            }   
        }
        $dfwrulespec.source_groups = $tmp
    }
    else {
        $dfwrulespec.source_groups = @("ANY")    
    }

    #Check destination ip or group name and add them to firewall spec

    if ($dfwdestinationIPs -ne "") {
        $dfwrulespec.destination_groups = @("")
        $tmp2 = @()
        $dfwdestinationIP = $dfwdestinationIPs.split(";")
        #$dfwrulename += "-" + $dfwdestinationIP[0].Replace("/","-")
        foreach ($dstip in $dfwdestinationIP) {
            $difipaddr = CheckIPAddress -IfIPaddress $dstip
            if ($difipaddr) {
                $tmp2 += @("$dstip")
            }
            else {
                if ($dstip -eq "") {
                }
                elseif ($dstip.toupper() -eq "ANY") {
                    $tmp2 = @("ANY")
                    break
                }
                else {
                    $dchecknsxtgroup = getnsxtgrouppath -nsxtgroupname $dstip
                    if ($dchecknsxtgroup -eq "invalid") {
                        Write-Host "Invalid Group Name - " $dstip
                        break
                    }
                    else {
                        $tmp2 += @($dchecknsxtgroup)
                    }
                }
            }   
        }
        $dfwrulespec.destination_groups = $tmp2
    }
    else {
        $dfwrulespec.destination_groups = @("ANY")    
    }

    #Specify firewall action based on rule

    if ($dfwruleaction.toupper() -eq "ALLOW") {
        $dfwrulespec.action = "ALLOW"
    }
    elseif ($dfwruleaction.toupper() -eq "DENY") {
        $dfwrulespec.action = "DROP"
    }
    elseif ($dfwruleaction.toupper() -eq "REJECT") {
        $dfwrulespec.action = "REJECT"   
    }
    elseif ($dfwruleaction.toupper() -eq "DROP") {
        $dfwrulespec.action = "DROP"
    }
    else {
        Write-Host "Invalid action status"
        break
    }

    #specify firewall sequence number
    #$dfwrulespec.rule_id = $dfwsequencenumber

    if ($dfwdirection.toupper() -eq "IN") {
        $dfwrulespec.direction = "IN"
    }
    elseif ($dfwdirection.toupper() -eq "OUT") {
        $dfwrulespec.direction = "OUT"
    }
    else {
        $dfwrulespec.direction = "IN_OUT"
    }

    #setup correct section in firewall rule section

    $dfwpolicydomainservice = Get-NsxtPolicyService com.vmware.nsx_policy.infra.domains
    $dfwpolicydomain = $dfwpolicydomainservice.list()
    $dfwpolicydomainname = $dfwpolicydomain.results | Where-Object {$_.display_name -eq "default"}
    $dfwpolicyservice = Get-NsxtPolicyService com.vmware.nsx_policy.infra.domains.security_policies
    $dfwpolicy = $dfwpolicyservice.list($dfwpolicydomainname.id)
    $dfwpolicyname = $dfwpolicy.results | Where-Object {$_.display_name -eq $dfwpolicysectname}

    #create service entries and add them to firewall rule spec

    $dfwpolicyservicegroupsvc = Get-NsxtPolicyService com.vmware.nsx_policy.infra.services
    #$dfwServiceEntL4Spec1 = $dfwpolicyservicegroupsvc.help.patch.service.service_entries.Element.l4_port_set_service_entry.Create()
    $dfwServiceEntL4Spec2 = $dfwpolicyservicegroupsvc.help.patch.service.service_entries.Element.l4_port_set_service_entry.Create()
    $serviceEntry = @()

    $dfwrulespec.services = @()
    #$tmp3 = @()
    <#
    if ($dfwsourceports -ne "") {
        if ($dfwsourceports.toupper() -ne "ANY") {
            $dfwsourceport = $dfwsourceports.split(";")
            $srcsvcid = $dfwportype.toupper()
            foreach ($srcport in $dfwsourceport) {
                if (!(checkport -Ifportnumber $srcport)) {
                    if ($srcport -eq "") {
                    }
                    else {
                        $dfwservicepath = getnsxtservice -nsxtservicename $srcport
                        if ($dfwservicepath -eq "invalid") {
                            Write-Host "Service with name is not found - " $srcport
                            break
                        }
                        else {
                            $dfwrulespec.services += @("$dfwservicepath")
                        }
                    }
                }
                else {
                    $tmp3 += @($srcport)
                    $srcsvcid += "-" + $srcport
                }
            }
            if ($tmp3 -ne "") {
                $dfwServiceEntL4Spec1.id = $srcsvcid
                $dfwServiceEntL4Spec1.destination_ports=@()
                $dfwServiceEntL4Spec1.l4_protocol = $dfwportype.toupper()
                $dfwServiceEntL4Spec1.source_ports = $tmp3
                $dfwServiceEntL4Spec1.resource_type = "L4PortSetServiceEntry"
                $serviceEntry += $dfwServiceEntL4Spec1 
            }   
        }
        else {
            $dfwrulespec.services = @("ANY")
            $sourceservicename = $dfwportype.toupper() + "-ANY"
        }
    }
    else {
        $dfwrulespec.services = @("ANY")
    }
    #>

    $tmp4 = @()
    if ($dfwdestports -ne "") {
        if ($dfwdestports.toupper() -ne "ANY") {
            $dfwdestport = $dfwdestports.split(";")
            $dstsvcid = $dfwportype.toupper()
            foreach ($destport in $dfwdestport) {
                if (!(checkport -Ifportnumber $destport)) {
                    if ($destport -eq "") {
                    }
                    else {
                        $dfwdservicepath = getnsxtservice -nsxtservicename $destport
                        if ($dfwdservicepath -eq "invalid") {
                            Write-Host "Service with name is not found - " $destport
                            break
                        }
                        else {
                            $dfwrulespec.services += @("$dfwdservicepath")
                        }    
                    }
                }
                else {
                    $tmp4 += @($destport)
                    $dstsvcid += "-" + $destport
                }   
            }
            if ($tmp4 -ne "") {
                $dfwServiceEntL4Spec2.id = $dstsvcid
                $dfwServiceEntL4Spec2.destination_ports=$tmp4
                $dfwServiceEntL4Spec2.l4_protocol = $dfwportype.toupper()
                $dfwServiceEntL4Spec2.source_ports = @()
                $dfwServiceEntL4Spec2.resource_type = "L4PortSetServiceEntry"
                $serviceEntry += $dfwServiceEntL4Spec2
            }
        }
        else {
            $dfwrulespec.services = @("ANY")
            $destservicename = $dfwportype.toupper() + "-ANY"
        }
    }
    else {
        $dfwrulespec.services = @("ANY")
    }
    
    $dfwrulespec.service_entries = $serviceEntry
    $dfwrulespec.display_name = $dfwrulename
    if ($dfwrulespec.services.count -eq 0) {
        $dfwrulespec.services = @("ANY")
    }
    Write-Host -ForegroundColor Green "Current rule Specification going to be created -"
    $dfwrulespec

    $dfwrulecreate = $dfwpolicyfirewallsvc.patch($dfwpolicydomainname.id,$dfwpolicyname.id,$dfwrulespec.display_name,$dfwrulespec)
    Write-Host $dfwrulecreate
    Start-Sleep -Seconds 5
}