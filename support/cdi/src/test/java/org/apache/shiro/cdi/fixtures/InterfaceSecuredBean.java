/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.cdi.fixtures;


import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.apache.shiro.aop.fixtures.SecuredInterface;

/**
 * Secured only through {@link SecuredInterface}; also declares a producer and an observer that must be
 * registered exactly once after the synthetic replacement.
 */
@ApplicationScoped
public class InterfaceSecuredBean implements SecuredInterface {
    @Inject
    private Counter counter;

    @Override
    public String adminOnly() {
        return "admin:" + (counter != null);
    }

    @Produces
    @Named("fromInterfaceSecuredBean")
    public String produced() {
        return "produced";
    }

    public void onPing(@Observes Ping ping) {
        counter.increment();
    }
}
