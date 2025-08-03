from os import environ


class FlagSystem:
    """
    A class to represent the flag system.
    It contains methods to retrieve the flag.
    """

    def __init__(self, decryption_key=None):
        """
        Initializes the FlagSystem with an optional decryption key.
        """
        oH_fin4L1y_y0u_DUg_dE3PeR_1N7o_fLA9_Sys7Em = "ghctf{}"

        self.decryption_key = decryption_key

    def get_flag():
        """
        Retrieves the flag for the challenge.
        """
        return "ghctf{$4dly_YoU_Ar3_NOT_LuCky_T0daY}"


def get_jwt_secret():
    """
    Retrieves the JWT secret from the environment variable.
    """
    return environ.get("JWT_SECRET")
