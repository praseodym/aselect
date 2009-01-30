package org.aselect.system.logging;

import java.util.logging.Level;

public class Audit extends Level {
    // Create the new level
    public static final Level AUDIT = new Audit("AUDIT", Level.INFO.intValue()+10);

    public Audit(String name, int value) {
        super(name, value);
    }
    
    // TODO parse int (Level.INFO.intValue()+10) value supplied as string
    public static Level parse(String name) throws IllegalArgumentException {
    	if ("AUDIT".equalsIgnoreCase(name)) {
    		return AUDIT;
    	} else
    		return Level.parse(name);
    }

}
