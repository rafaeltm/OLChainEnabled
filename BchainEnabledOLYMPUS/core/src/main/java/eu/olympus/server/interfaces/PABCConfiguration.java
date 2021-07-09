package eu.olympus.server.interfaces;

import eu.olympus.model.AttributeDefinition;
import java.util.Set;

public interface PABCConfiguration extends PESTOConfiguration {

	public int getServerCount();

	public Set<AttributeDefinition> getAttrDefinitions();

	public byte[] getSeed();
	
	public long getLifetime();
	
	public long getAllowedTimeDifference();

	public String didSetup();

	String getVidpName();

	boolean getUseBchain();
	
}
