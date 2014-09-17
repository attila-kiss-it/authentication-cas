/**
 * This file is part of Everit - CAS authentication tests.
 *
 * Everit - CAS authentication tests is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - CAS authentication tests is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - CAS authentication tests.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authentication.http.cas.sample;

import java.util.Optional;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.resource.resolver.ResourceIdResolver;

@Component(name = "CasResourceIdResolver", metatype = false,
        configurationFactory = false, policy = ConfigurationPolicy.IGNORE, immediate = true)
@Service
public class CasResourceIdResolver implements ResourceIdResolver {

    public static final String JOHNDOE = "johndoe";

    public static final Optional<Long> JOHNDOE_RESOURCE_ID = Optional.of(123L);

    @Override
    public Optional<Long> getResourceId(final String uniqueIdentifier) {
        if (uniqueIdentifier.equals(JOHNDOE)) {
            return JOHNDOE_RESOURCE_ID;
        }
        return Optional.empty();
    }

}
