#!/usr/bin/env -S python3 -B

import sys
import PySimpleGUI as sg
import dissector as dis

if __name__ == '__main__':
    sg.theme('SystemDefaultForReal')
    layout = [
        [sg.T("Input:         "), sg.Input(key="infile",size=(45, 1)), sg.FileBrowse(key="infile", file_types=[("RAW-File", "*.*")])],
        [sg.T("Output:      "), sg.Input(key="outfile",size=(45, 1)), sg.FileSaveAs(key="outfile", file_types=[("ASM-File", "*.a")])],
        [sg.T("Labels:      "), sg.Input(key="labs", size=(45, 1)), sg.FileBrowse(key="labs", file_types=[("Label-File", "*.json")])],
        [sg.T("")],
        [sg.T("Stardaddress in HEX:"), sg.T("$"), sg.Input(key="startaddy", justification='right', size=(4, 1))],
        [sg.T("Offset in HEX:           "), sg.T("$"), sg.Input(key="-offset-", justification='right', size=(4, 1))],
        [sg.T("Limit in HEX:            "), sg.T("$"), sg.Input(key="-limit-", justification='right', size=(4, 1))],
        [sg.T("")],
        [sg.T("Assembler Type")],
        [sg.Radio('Acme', 1, enable_events=True, key='-acme-', default=True), sg.Radio('Kick Assembler', 1, enable_events=True, key='-kick-')],
        [sg.T("Options")],
        [sg.Checkbox('Show memory dump  ', default=False, key="-dump-"), sg.Checkbox('Use illegal Opcodes', default=False, key="-illegals-")],
        [sg.Checkbox('Show label list           ', default=False, key="-labellist-"), sg.Checkbox('Show cycles', default=False, key="-cycles-")],
        [sg.T("")],
        [sg.Button("Dissect!")]
    ]

    window = sg.Window('Dissector V1.00', layout, size=(510, 440))

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "Exit":
            break
        elif event == "Dissect!":
            input_file = values["infile"]
            output_file = values["outfile"]
            startaddress = values["startaddy"]

            #clear up
            sys.argv = [sys.argv[0]]

            sys.argv.extend([input_file, output_file, startaddress])
        
            if (input_file == '') or (output_file == '') or (startaddress == ''):
                sg.popup('Inputfile, Outputfile or Startaddress cant be empty!')
                continue

            if values["labs"] != '':
                sys.argv.extend(['-lf'])
                sys.argv.extend([values["labs"]])
            if values["-offset-"] != '':
                sys.argv.extend(['-o'])
                sys.argv.extend([values["-offset-"]])
            if values["-limit-"] != '':
                sys.argv.extend(['-l'])
                sys.argv.extend([values["-limit-"]])
            if values["-acme-"] == True:
                sys.argv.extend(['-t'])
                sys.argv.extend(['acme'])
            else:
                sys.argv.extend(['-t'])
                sys.argv.extend(['kickass'])
            if values["-dump-"] == True:
                sys.argv.extend(['-d'])
            if values["-illegals-"] == True:
                sys.argv.extend(['-i'])
            if values["-labellist-"] == True:
                sys.argv.extend(['-ll'])
            if values["-cycles-"] == True:
                sys.argv.extend(['-cc'])

            #sg.popup(sys.argv)
            dis._main_procedure()


            sg.popup('All done!')
