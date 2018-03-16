/*
 * Copyright (c) 2018, UNSW. (https://www.unsw.edu.au/) All Rights Reserved.
 *
 * UNSW. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.ayyoob.sdn.of.simulator.processor.mud;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TcpMatch {

	@JsonProperty("destination-port")
	private PortMatch destinationPortMatch;

	@JsonProperty("ietf-mud:direction-initiated")
	private String directionInitialized;

	@JsonProperty("source-port")
	private PortMatch sourcePortMatch;

	public PortMatch getDestinationPortMatch() {
		return destinationPortMatch;
	}

	public void setDestinationPortMatch(PortMatch destinationPortMatch) {
		this.destinationPortMatch = destinationPortMatch;
	}

	public PortMatch getSourcePortMatch() {
		return sourcePortMatch;
	}

	public void setSourcePortMatch(PortMatch sourcePortMatch) {
		this.sourcePortMatch = sourcePortMatch;
	}

	public String getDirectionInitialized() {
		return directionInitialized;
	}

	public void setDirectionInitialized(String directionInitialized) {
		this.directionInitialized = directionInitialized;
	}
}
