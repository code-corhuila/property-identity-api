package co.edu.corhuila.property.identity.application.port.in;

/** Login, renewal and logout (E-11, E-12, E-13). */
public final class SessionUseCases {

    private SessionUseCases() { }

    public interface Login {
        AuthSession login(String email, String password);
    }

    public interface Refresh {
        AuthSession refresh(String refreshToken);
    }

    /** refreshToken closes one session of the caller; allDevices closes all of them. */
    public interface Logout {
        void logout(Caller caller, String refreshToken, boolean allDevices);
    }
}
