package org.aselect.server.request.handler.xsaml20;

import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;
import javax.servlet.ServletConfig;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

//
//
public abstract class Saml20_BaseHandler extends ProtoRequestHandler
{
	private final static String MODULE = "Saml20_BaseHandler";

	// RH, 20080602
	// We (Bauke and I) decided that default should be NOT to verify
	// SAML2 says it SHOULD be singed
	private boolean _bVerifySignature = false;
	private boolean _bVerifyInterval = false; // Checking of Saml2 NotBefore and NotOnOrAfter 	
	private Long maxNotBefore = null; 	// relaxation period before NotBefore, validity period will be extended with this value (seconds)
										// if null value is not specified in aselect.xml
	private Long maxNotOnOrAfter = null; 	// relaxation period after NotOnOrAfter, validity period will be extended with this value (seconds)
											// if null value is not specified in aselect.xml
	
	/**
	 * Init for class Saml20_BaseHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oHandlerConfig
	 *            Object
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
			throws ASelectException {
		String sMethod = "init()";

		super.init(oServletConfig, oHandlerConfig);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "OpenSAML library could not be initialized", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		//		_bVerifySignature = true;
		String sVerifySignature = HandlerTools.getSimpleParam(oHandlerConfig, "verify_signature", false);
		//		if (sVerifySignature != null && sVerifySignature.equalsIgnoreCase("false")) {
		//			_bVerifySignature = false;
		if ("true".equalsIgnoreCase(sVerifySignature)) {
			set_bVerifySignature(true);
		}
		String sIntervalInterval = HandlerTools.getSimpleParam(oHandlerConfig, "verify_interval", false);
		if ("true".equalsIgnoreCase(sIntervalInterval)) {
			set_b_VerifyInterval(true);
		}

		String sMaxNotBefore = HandlerTools.getSimpleParam(oHandlerConfig, "max_notbefore", false);
		if (sMaxNotBefore != null) {
			setMaxNotBefore(new Long( Long.parseLong(sMaxNotBefore) * 1000));
		}
		String sMaxNotOnOrAfter = HandlerTools.getSimpleParam(oHandlerConfig, "max_notonorafter", false);
		if (sMaxNotOnOrAfter != null) {
			setMaxNotOnOrAfter(new Long( Long.parseLong(sMaxNotOnOrAfter) * 1000) );
		}
	}

	// Unfortunately, sNameID is not equal to our tgtID (it's the Federation's)
	// So we have to search all TGT's (for now a very inefficient implementation) TODO
	protected int removeTgtByNameID(String sNameID)
	throws ASelectStorageException
	{
		String sMethod = "removeByNameID";
		TGTManager tgtManager = TGTManager.getHandle();
		HashMap allTgts = tgtManager.getAll();

		// For all TGT's
		int found = 0;
        Set keys = allTgts.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
		//for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
		//	String sKey = e.nextElement();
			HashMap htTGTContext = (HashMap) tgtManager.get(sKey);
			String tgtNameID = (String) htTGTContext.get("name_id");
			if (sNameID.equals(tgtNameID)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Remove TGT="+Utils.firstPartOf(sKey, 30));
				tgtManager.remove(sKey);
				found = 1;
				break;
			}
		}
		return found;
	}

	/**
	 * Process logout request. <br>
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @param response
	 *            HttpServletResponse
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	//	public abstract RequestState process(HttpServletRequest request, HttpServletResponse response)
	//	throws ASelectException;
	/*	{
	 String sMethod = "process()";
	 return null;
	 }*/

	public void destroy() {
	}

	public synchronized boolean is_bVerifySignature() {
		return _bVerifySignature;
	}

	public synchronized void set_bVerifySignature(boolean verifySignature) {
		_bVerifySignature = verifySignature;
	}

	public synchronized boolean is_bVerifyInterval() {
		return _bVerifyInterval;
	}

	public synchronized void set_b_VerifyInterval(boolean verifyInterval) {
		_bVerifyInterval = verifyInterval;
	}

	public synchronized Long getMaxNotBefore() {
		return maxNotBefore;
	}

	public synchronized void setMaxNotBefore(Long maxNotBefore) {
		this.maxNotBefore = maxNotBefore;
	}

	public synchronized Long getMaxNotOnOrAfter() {
		return maxNotOnOrAfter;
	}

	public synchronized void setMaxNotOnOrAfter(Long maxNotOnOrAfter) {
		this.maxNotOnOrAfter = maxNotOnOrAfter;
	}
}
