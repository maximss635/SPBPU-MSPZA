import signify.authenticode.signed_pe


def check_sign(path):
    try:
        with open(path, "rb") as f:
            pefile = signify.authenticode.signed_pe.SignedPEFile(f)
            status, err = pefile.explain_verify()

        return status == signify.authenticode.signed_pe.AuthenticodeVerificationResult.OK, err
    except FileNotFoundError:
        return False, "Unknown"
    except Exception as err:
        return False, err


if __name__ == '__main__':
    # check_sign("/home/m/all/ibks/5year/МСПЦА/3/exescaner/test/hello_world")

    result = check_sign("/home/m/all/ibks/5year/МСПЦА/3/exescaner/test/exe_test.exe")
    print(result)
