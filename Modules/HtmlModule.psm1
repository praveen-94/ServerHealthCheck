Function UpdateHTMLTableCells 
{ Param([Parameter(Mandatory = $True, ValueFromPipeline = $True)][string] $HTML)
  $CustomLogic = @{
        "Stopped"  = ' style="background-color: #F8D7DA; color: #721C24;">Stopped<'
        "Running"  = ' style="background-color: #D4EDDA; color: #15572a;">Running<'
        "Error"    = ' style="background-color: #F8D7DA; color: #721C24;">Error<'
        "Warning"  = ' style="background-color: #FFF3CD; color: #856404;">Warning<'
    }

    #Extract only the <table> content
    if($HTML -match "(<table[\s\S]*?>[\s\S]*?</table>)") 
    { $TableHTML = $matches[1]
    } 
    else 
    { Write-Error "No valid <table> found in the provided HTML."
      return
    }

    try 
    { $XML = [xml]"<?xml version='1.0' encoding='utf-8' ?><root>$TableHTML</root>"
    } 
    catch 
    { Write-Error "Failed to parse HTML as XML. Ensure it is valid."
      return
    }

    #Ensure <table> exists in parsed XML
    if(-not $XML.root.table) 
    { Write-Error "No <table> found in the parsed XML."
      return
    }

    #Iterate through rows and cells
    foreach($Row in $XML.root.table.tr) 
    { foreach ($Cell in $Row.td) 
      { if($Cell -and $Cell.InnerText) 
        { $Value = $Cell.InnerText.Trim()
          if($CustomLogic.ContainsKey($Value)) 
          { $Cell.InnerXml = "<td" + $CustomLogic[$Value] + "</td>"
          }
        }
      }
    }
    return ($XML.root.InnerXml)
}

Function AddHTMLTableAttribute 
{ #add a custom attribute such as ID or Class to your auto-generated table(s).
  #Example Usage: $WMI = [WMI Query] | ConvertTo-HTML -Fragment | Out-String | Add-HTMLTableAttribute -AttributeName 'id' -Value 'tab-system-cpu';
  Param([Parameter(Mandatory = $True, ValueFromPipeline = $True)][string] $HTML,[string] $AttributeName,[string] $Value)
  $XML = [xml]$HTML 
  $Attribute = $XML.CreateAttribute($AttributeName)
  $Attribute.Value = $Value 
  $XML.Table.Attributes.Append($Attribute) | Out-Null
  Return ($XML.OuterXML | Out-String)
}

Function AddPreContentMessage 
{ # add Pre-Content HTML directly above the Table output by displaying a banner with text and an image.
  # It allows you to change the Image ,Colour and Text of the banner using one of the 3 switches (Below)
  # Error: Red Banner, Red Text, traditional Error Icon, Information: Blue Banner, Blue Text, traditional Information Icon, Warning: Amber Banner, Amber Text, traditional Warning Icon
  # Example Usage: $WMI = [WMI Query] | ConvertTo-HTML -Fragment -PreContent (Add-PreContentMessage -Type "Information" -Message "Displaying data for drive C: only.");
  Param([Parameter(Mandatory = $True, ValueFromPipeline = $True)][String] $Type,[String] $Message)
  Switch($Type) 
  { "Error"       { $PreContent = "<section class='pre-content-alert-error'><div class='pre-content-alert-image-error'></div><span class='pre-content-alert-text-error'>$Message</span></section>"                   }
    "Information" { $PreContent = "<section class='pre-content-alert-information'><div class='pre-content-alert-image-information'></div><span class='pre-content-alert-text-information'>$Message</span></section>" }
    "Warning"     { $PreContent = "<section class='pre-content-alert-warning'><div class='pre-content-alert-image-warning'></div><span class='pre-content-alert-text-warning'>$Message</span></section>"             }
  } 
  Return $PreContent | Out-String;
}
