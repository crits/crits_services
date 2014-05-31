<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<!-- This XSLT will convert a PDML file, saved by Wireshark, into
     HTML. The HTML page should look like Wireshark. For questions contact
     Dirk Jagdmann (doj@cubic.org).
     Version: 2010-06-09 -->

<!-- set parameters of the HTML output -->
<xsl:output method="html" encoding="UTF-8" omit-xml-declaration="no" standalone="yes" indent="yes"/>

<!-- this matches the "field" tag -->
<xsl:template match="field">
  &#160;&#160;&#160; <!-- indent with 3 non-breaking spaces -->

  <!-- output either the "showname" or "show" attribute -->
  <xsl:choose>
    <xsl:when test="string-length(@showname)>0">
      <xsl:value-of select="@showname"/><br/>
    </xsl:when>
    <xsl:otherwise>
      <!--<xsl:value-of select="@name"/>:--> <xsl:value-of select="@show"/><br/>
    </xsl:otherwise>
  </xsl:choose>

  <xsl:apply-templates/> <!-- we expect to match "field" tags -->
</xsl:template>

<!-- this matches the "packet" tag -->
<xsl:template match="packet">

  <!-- declare some variables for later use -->
  <xsl:variable name="frame_num" select="proto[@name='frame']/field[@name='frame.number']/@show"/>
  <xsl:variable name="frame_id"  select="concat('f',$frame_num)"/>
  <xsl:variable name="frame_c"   select="concat($frame_id,'c')"/>
  <xsl:variable name="colorname" select="proto[@name='frame']/field[@name='frame.coloring_rule.name']/@show"/>

  <!-- the "title" bar of the frame -->
  <div width="100%" id="{$frame_id}" style="border: 1px solid #bbb;border-bottom: 0px;">
      <span class="frame_bg" style="display:inline-block; width: 100%;">
        <xsl:attribute name="data-color"><xsl:value-of select="$colorname" /></xsl:attribute>
        <a style="display: inline-block;" class="ui-icon ui-icon-triangle-1-e" href="javascript:toggle_node('{$frame_c}')"></a>
        Frame <xsl:value-of select="$frame_num"/>:
        <xsl:for-each select="proto[@name!='geninfo']">
          <xsl:value-of select="@name"/>,
        </xsl:for-each>
    </span>
    <!--<small><a href="javascript:hide_node('{$frame_id}')">[X]</a></small> -->

    <!-- the frame contents are stored in a div, so we can toggle it -->
    <div width="100%" id="{$frame_c}" style="display:none">
      <!-- loop trough all proto tags, but skip the "geninfo" one -->
      <xsl:for-each select="proto[@name!='geninfo']">

        <xsl:variable name="proto" select="concat($frame_id,@name)"/>

        <!-- the "title" bar of the proto -->
        <div width="100%" style="background-color:#e5e5e5; margin-bottom: 2px">
          <span style="display:inline-block; width: 100%;">
              &#160;<a style="display: inline-block;" class="ui-icon ui-icon-triangle-1-e" href="javascript:toggle_node('{$proto}')"></a>&#160;<xsl:value-of select="@showname"/>
          </span>

          <!-- print "proto" details inside another div -->
          <div width="100%" id="{$proto}" style="display:none">
           <xsl:apply-templates/> <!-- we expect to match "field" tags -->
          </div>
        </div>
      </xsl:for-each>
    </div>

  </div>

</xsl:template>

<xsl:template match="pdml">
  <!--Capture Filename: <b><xsl:value-of select="@capture_file"/></b> -->
  <font size="2.5">&#160;PDML created: <b><xsl:value-of select="@time"/></b></font>
  <tt>
    <xsl:apply-templates/> <!-- we expect to match the "packet" nodes -->
  </tt>
</xsl:template>

<!-- this block matches the start of the PDML file -->
<xsl:template match="/">
  <html>
  <head>
    <title>poor man's Wireshark</title>
    <script type="text/javascript">
        function toggle_node(node) {
            $("#" + node).toggle();
            $("#" + node).siblings('span:first').children('a').toggleClass('ui-icon-triangle-1-e');
            $("#" + node).siblings('span:first').children('a').toggleClass('ui-icon-triangle-1-s');
        }
        $('.frame_bg').each(function(e) {
            console.log($(this).attr('data-color'));
        });
    </script>
  </head>
    <body>
      <xsl:apply-templates/> <!-- we expect to match the "pdml" node -->
    </body>
  </html>
</xsl:template>

</xsl:stylesheet>
