package cc.mrbird.febs.system.entity;

import cc.mrbird.febs.common.converter.TimeConverter;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.wuwenze.poi.annotation.Excel;
import com.wuwenze.poi.annotation.ExcelField;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Date;

/**
 * @author MrBird
 */
@Data
@TableName("t_dept")
@Excel("部门信息表")
public class Dept implements Serializable {

    public static final Long TOP_NODE = 0L;
    private static final long serialVersionUID = 5702271568363798328L;
    /**
     * 部门 ID
     */
    @TableId(value = "DEPT_ID", type = IdType.AUTO)
    private Long deptId;

    /**
     * 上级部门 ID
     */
    @TableField("PARENT_ID")
    private Long parentId;

    /**
     * 部门名称
     */
    @TableField("DEPT_NAME")
    @NotBlank(message = "{required}")
    @Size(max = 10, message = "{noMoreThan}")
    @ExcelField(value = "部门名称")
    private String deptName;

    /**
     * 看板过滤条件
     */
    @TableField("DASHBOARD_FILTER")
    @Size(max = 100, message = "{noMoreThan}")
    @ExcelField(value = "看板过滤条件")
    private String dashboardFliter;

    /**
     * 看板id
     */
    @TableField("DASHBOARD_ID")
    @ExcelField(value = "看板id")
    private Long dashboardId;

    /**
     * public_uuid
     */
    @TableField("PUBLIC_UUID")
    @ExcelField(value = "public_uuid")
    private String publicUuid;

    /**
     * 排序
     */
    @TableField("ORDER_NUM")
    private Long orderNum;

    /**
     * 创建时间
     */
    @TableField("CREATE_TIME")
    @ExcelField(value = "创建时间", writeConverter = TimeConverter.class)
    private Date createTime;

    @TableField("MODIFY_TIME")
    @ExcelField(value = "修改时间", writeConverter = TimeConverter.class)
    private Date modifyTime;

}
