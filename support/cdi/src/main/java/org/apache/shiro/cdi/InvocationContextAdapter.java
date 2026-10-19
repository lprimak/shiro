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
package org.apache.shiro.cdi;


import jakarta.interceptor.InvocationContext;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.aop.MethodInvocation;

import java.lang.reflect.Method;

/**
 * Adapts a CDI {@link InvocationContext} to a Shiro {@link MethodInvocation}.
 */
@RequiredArgsConstructor
class InvocationContextAdapter implements MethodInvocation {
    private final InvocationContext context;

    @Override
    public Object proceed() throws Throwable {
        return context.proceed();
    }

    @Override
    public Method getMethod() {
        return context.getMethod();
    }

    @Override
    public Object[] getArguments() {
        return context.getParameters();
    }

    @Override
    public Object getThis() {
        return context.getTarget();
    }

    @Override
    public String toString() {
        return "Method invocation [" + context.getMethod() + "]";
    }
}
