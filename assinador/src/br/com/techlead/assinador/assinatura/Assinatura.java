package br.com.techlead.assinador.assinatura;

public class Assinatura {
    private byte[] assinatura;
    private byte[] envelope;

    Assinatura(byte[] _assinatura, byte[] _envelope) {
        this.assinatura = _assinatura;
        this.envelope = _envelope;
    }

    Assinatura(byte[] _envelope) {
        this.assinatura = _envelope;
    }

    public byte[] getAssinatura() {
        return this.assinatura;
    }

    public void setAssinatura(byte[] _assinatura) {
        this.assinatura = _assinatura;
    }

    public byte[] getEnvelope() {
        return this.envelope;
    }

    public void setEnvelope(byte[] _envelope) {
        this.envelope = _envelope;
    }
}

