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
public class PortMatch {
	private String operator;
	private int port;

	@JsonProperty("lower-port")
	private int lowerPort;

	@JsonProperty("upper-port")
	private int upperPort;

	public String getOperator() {
		return operator;
	}

	public void setOperator(String operator) {
		this.operator = operator;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public int getLowerPort() {
		return lowerPort;
	}

	public void setLowerPort(int lowerPort) {
		this.lowerPort = lowerPort;
	}

	public int getUpperPort() {
		return upperPort;
	}

	public void setUpperPort(int upperPort) {
		this.upperPort = upperPort;
	}
}
