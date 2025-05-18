from bitarray import bitarray
import helpers.user_interface as ui

# Trabalho 1 de Segurança Computacional feito por 
# Eduardo Pereira - 231018937 
# Luca Megiorin - 231003390

def main():
    while True:
        choice = ui.main_ui()
        match choice:
            case 1:
                ui.sdes_ui()
            case 2:
                ui.op_ui()
            case _:
                return

if __name__ == "__main__":
    main()
