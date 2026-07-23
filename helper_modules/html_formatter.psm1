Function AddPreContentMessage
{ # An icon + text banner for -PreContent, directly above a table. -Type picks the styling:
  # Error (red), Information (blue) or Warning (amber).
  # e.g. [query] | ConvertTo-HTML -Fragment -PreContent (AddPreContentMessage -Type "Information" -Message "Drive C: only.")
  Param([Parameter(Mandatory = $True, ValueFromPipeline = $True)][String] $Type,[String] $Message)
  Switch($Type) 
  { "Error"       { $PreContent = "<section class='pre-content-alert-error'><div class='pre-content-alert-image-error'></div><span class='pre-content-alert-text-error'>$Message</span></section>"                   }
    "Information" { $PreContent = "<section class='pre-content-alert-information'><div class='pre-content-alert-image-information'></div><span class='pre-content-alert-text-information'>$Message</span></section>" }
    "Warning"     { $PreContent = "<section class='pre-content-alert-warning'><div class='pre-content-alert-image-warning'></div><span class='pre-content-alert-text-warning'>$Message</span></section>"             }
  } 
  Return $PreContent | Out-String;
}
