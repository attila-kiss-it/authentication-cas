package org.everit.osgi.authentication.cas.internal;

public class TicketValidationException extends Exception {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = -3180080337626141284L;

    public TicketValidationException(final String reason) {
        super("Failed to validate ticket: [" + reason + "]");
    }

}
