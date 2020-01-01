# STILL A WORK IN PROGRESS...

# Home Assistant integration - Clas Ohlson
Integration for Clas Ohlsons smart plugs (bulbs will come as soon as I get one)


Installation instructions:
- Create the directory "custom_components" in your config folder for Home Assistant
- Copy the folder Clas and all its files to custom_copmponents folder. 
- Restart Home Assistant
- To add components, edit your configuration.yaml and add the following:

````
switch:
  - platform: clas
    host: IP_OF_YOUR_COMPONENT
    mac: MAC_ADDR_FOR_COMPONENT
    type: sp4/sp2/sp3
    friendly_name: "Name for your component"
````
