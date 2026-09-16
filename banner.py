import os

# Habilita soporte de color TrueColor en Windows CMD/PowerShell
os.system('')

COLOR_IMAGEN = "\033[38;2;137;207;240m"
RESET = "\033[0m"

SIMBOLO = r"""
                 █▒█                 
               ▒██ ▒░                
             █ █ ▒   █ ░             
            ▒░ █ █     ░░▒           
          ▒▒ ▒  ░█   █ ▒ ░░          
        ▓▒░░░░   ▓   █ ░░░░░░        
      ▓░░  ░░░ █▒▓   █ ░░░ ░░░░      
    █░░░░░░▒    █▓  ▒    ░░░░░░░░    
  █░░ ░░░▒ ▓▒▒█░ █   ▒▓░▓▒▓▒░▒░░░░▒  
    ░░▒▒░      ▒▒▒ ▓▒▒       ▓░▒▒░░░ 
  ░▒▒                           ▒░░▒ 
 ▒▒                               █▓ 
"""

TITULO = r"""
  ▓▓▓  ▓▓▓   ▓▓▓  ▓▓▓       ▓▓▓▓ ▓▓▓▓▓ ▓   ▓ ▓▓▓▓▓ ▓▓▓ ▓   ▓ ▓▓▓▓▓ ▓       
   ▓░░▓ ░░▓ ▓ ░░░  ▓░░     ▓ ░░░░▓░░░░░▓▓  ▓░ ░▓░░░ ▓░░▓▓  ▓░▓░░░░░▓░      
   ▓░░▓▓▓▓▓░▓░ ▓▓░ ▓░░▓▓▓▓  ▓▓▓░░▓▓▓▓░░▓░▓ ▓░░ ▓░░░░▓░░▓░▓ ▓░▓▓▓▓░░▓░░     
▓  ▓░░▓░░░▓░▓░░ ▓░ ▓░░ ░░░░  ░░▓ ▓░░░░ ▓░░▓▓░░ ▓░░  ▓░░▓░░▓▓░▓░░░░ ▓░░     
 ▓▓ ░░▓░░░▓░░▓▓▓ ░▓▓▓░  ░░░▓▓▓▓░░▓▓▓▓▓░▓░░ ▓░░ ▓░░ ▓▓▓░▓░░ ▓░▓▓▓▓▓░▓▓▓▓▓   
  ░░ ░ ░░  ░░ ░░░ ░░░░      ░░░░ ░░░░░░ ░░  ░░  ░░  ░░░ ░░  ░░░░░░░ ░░░░░  
   ░░   ░   ░  ░░░  ░░░      ░░░░  ░░░░░ ░   ░   ░   ░░░ ░   ░ ░░░░░ ░░░░░ 
"""


def generar_banner_lado_a_lado(simbolo_str, titulo_str, espaciado=4, color=True):
    l_simbolo = [linea for linea in simbolo_str.strip("\n").split("\n")]
    ancho_simbolo = max(len(linea) for linea in l_simbolo)

    # 1. Construir únicamente el cuadro para el símbolo
    borde_sup = "▐" + "▀" * ancho_simbolo + "▌"
    borde_inf = "▐" + "▄" * ancho_simbolo + "▌"

    l_marco = [borde_sup]
    for linea in l_simbolo:
        l_marco.append(f"▐{linea.ljust(ancho_simbolo)}▌")
    l_marco.append(borde_inf)

    # 2. Preparar el título
    l_titulo = [linea for linea in titulo_str.strip("\n").split("\n")]

    # 3. Alineación vertical del título respecto al marco
    ancho_marco = len(borde_sup)
    total_lineas = max(len(l_marco), len(l_titulo))
    offset = (len(l_marco) - len(l_titulo)) // 2

    lineas_unidas = []
    for i in range(total_lineas):
        izq = l_marco[i] if i < len(l_marco) else " " * ancho_marco
        der = l_titulo[i - offset] if offset <= i < offset + len(l_titulo) else ""
        lineas_unidas.append(f"{izq}{' ' * espaciado}{der}")

    texto = "\n".join(lineas_unidas)
    return f"{COLOR_IMAGEN}{texto}{RESET}" if color else texto


def mostrar_banner():
    print(generar_banner_lado_a_lado(SIMBOLO, TITULO))


def texto_banner_plano():
    """Igual que mostrar_banner(), pero sin los códigos de color ANSI
    (para usarlo en la terminal falsa de la página web)."""
    return generar_banner_lado_a_lado(SIMBOLO, TITULO, color=False)


if __name__ == "__main__":
    mostrar_banner()
