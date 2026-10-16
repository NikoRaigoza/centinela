"""Qué hace Centinela con un correo según su nivel de riesgo y la configuración del buzón."""
from __future__ import annotations

from dataclasses import dataclass

from centinela.dominio.buzon import ModoCuarentena
from centinela.dominio.riesgo import NivelRiesgo


@dataclass(frozen=True)
class Acciones:
    cuarentena: bool = False            # mover a Centinela/Cuarentena (nunca se borra)
    etiquetar_sospechoso: bool = False  # dejar en la bandeja con la etiqueta Centinela/Sospechoso
    avisar: bool = False                # aviso al dueño del buzón

    @property
    def descripcion(self) -> str:
        if self.cuarentena:
            return ("Lo movimos a la carpeta «Centinela/Cuarentena» de tu Gmail. No se borró: "
                    "si es legítimo, puedes devolverlo a tu bandeja desde el panel de Centinela.")
        if self.etiquetar_sospechoso:
            return "Lo dejamos en tu bandeja con la etiqueta «Centinela/Sospechoso». No abras sus enlaces ni adjuntos."
        return "No fue necesario tomar ninguna acción."


def decidir_acciones(nivel: NivelRiesgo, modo: ModoCuarentena, avisar_por_correo: bool) -> Acciones:
    if nivel is NivelRiesgo.ALTO:
        automatica = modo is ModoCuarentena.CUARENTENA_AUTOMATICA
        return Acciones(cuarentena=automatica, etiquetar_sospechoso=not automatica, avisar=avisar_por_correo)
    if nivel is NivelRiesgo.MEDIO:
        return Acciones(etiquetar_sospechoso=True)
    return Acciones()
