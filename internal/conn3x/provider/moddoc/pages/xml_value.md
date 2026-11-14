Use `xml_value` to own one attribute, or one element's text, in an XML config file and leave the rest alone: a Tomcat connector's protocol, a Jenkins setting, a Maven mirror. Every byte the step doesn't own stays as it was, comments, the XML declaration and indentation included, so a diff of the file shows only your change. It's `community.general.xml` for one value.

## Example usage

Change an attribute on the element that has another attribute:

```hcl
step "http2" {
  xml_value {
    path  = "/opt/tomcat/conf/server.xml"
    xpath = "/Server/Service/Connector[@port='8080']/@protocol"
    value = "HTTP/2"
  }
}
```

Set an element's text:

```hcl
step "executors" {
  xml_value {
    path  = "/var/lib/jenkins/config.xml"
    xpath = "/hudson/numExecutors"
    value = "4"
  }
}
```

Add an element, with the attribute it's picked by:

```hcl
step "access_log" {
  xml_value {
    path  = "/opt/tomcat/conf/server.xml"
    xpath = "/Server/Service/Engine/Valve[@className='org.apache.catalina.valves.AccessLogValve']/@pattern"
    value = "common"
  }
}
```
<!-- reference -->
## How it works

**The XPath.** A small part of XPath: from the root, one element name per step, each with `[@attr='value']` predicates or `[n]`, counted from 1, to pick one element, and `/@name` at the end for an attribute. Names match without their namespace prefix. More than one element matching a step is an error that says how to pick one. `//`, functions and the other axes aren't there.

**Setting.** An attribute is changed in place, in the quotes it had, or added after the element's last attribute. An element's text is replaced, and an empty element, `<a/>`, becomes `<a>value</a>`. Text is escaped as XML needs, so `a < b` is written `a &lt; b`. An element with child elements has no text to set, and saying so is an error. A value that's already right is left as it's written.

**Adding.** When only the last element is missing, it's added after its parent's last child and indented as that child is, with the attributes the predicate names. A deeper missing path is an error. A path can't pick an element by the attribute it sets: once set, the path would miss it and add another.

**Taking out.** `state = "absent"` removes the attribute, or the element with the line it was alone on. It does nothing when the path isn't there. The root element can't be taken out.

**The file.** It's read and written as [`line`](line.md) reads and writes, with the file's owner and mode kept, and it must be well-formed XML before Conn3x touches it. Every plan reads the file again, so a value changed by hand shows the step out of sync, and the next apply puts it back.

## Removal

Deleting an `xml_value` step leaves the value. With `on_remove = "delete"`, it takes the attribute or the element out.
