# SECTION CREATION PROTECTION RULE

## Description
This rule prevents from starting **powershell** with different switched but not for a particular *-EncodedCommand* switch usage by using **cmd**.

## Rule TCL
```
Rule {
    Process {
        Include OBJECT_NAME {
            -v "*PowerShell*"
        }
        Include PROCESS_CMD_LINE {
            -v "*-NoLogo*"
        }
        Include PROCESS_CMD_LINE {
            -v "*-File*"
        }
        Include PROCESS_CMD_LINE {
            -v "*-EncodedCommand*"
        }
        Include PROCESS_CMD_LINE {
            -v "*-Command*"
        }
        Exclude PROCESS_CMD_LINE {
            -v "*-EncodedCommand ZQBjAGgAbwAgACcASABlAGwAbABvACAARQB4AHAAZQByAHQAIABSAHUAbABlAHMAIABUAHIAYQBpAG4AaQBuAGcAIABHAHIAbwB1AHAAIQAhACcA"
        }
    }
    Target {
        Match SECTION {
            Include -access "CREATE" ; # Prevents section creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows CMD.
3. Run the following command:<br>
`powershell -NoLogo` --> (this should be blocked)<br>
`powershell -EncodedCommand ZQBjAGgAbwAgACcASABlAGwAbABvACAARQB4AHAAZQByAHQAIABSAHUAbABlAHMAIABUAHIAYQBpAG4AaQBuAGcAIABHAHIAbwB1AHAAIQAhACcA` --> (this should NOT be blocked)<br>

## Notes
To generate the encoded string to be used with the *-EncodedCommand* switch, you can use powershell and run the following sequence of commands.<br>
`$command = "echo 'Hello this is the command to be encoded!!'"`<br>
`$bytes = [Text.Encoding]::Unicode.GetBytes($command)`<br>
`$encodedCommand = [Convert]::ToBase64String($bytes)`<br>
`echo $encodedCommand`<br>